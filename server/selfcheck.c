#define _GNU_SOURCE
#include "chunkd-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <syslog.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <tcutil.h>
#include <tchdb.h>
#include "chunkd.h"

struct chk_arg {
	time_t period;
	TCHDB *hdb;
	// GThread *gthread;
};

struct chk_tls {
	struct chk_arg *arg;

	int stat_ok;
	int stat_conflict;
};

static void chk_list_objs(struct chk_tls *tls, uint32_t table_id)
{
	struct fs_obj_lister lister;
	char *fn;
	char *csum, *csum_act;
	char *owner;
	unsigned long long size;
	time_t mtime;
	void *key_in;
	size_t klen_in;
	struct objcache_entry *cep;
	int rc;

	memset(&lister, 0, sizeof(struct fs_obj_lister));
	rc = fs_list_objs_open(&lister, chunkd_srv.vol_path, table_id);
	if (rc) {
		applog(LOG_WARNING, "Cannot open table %u: %s", table_id,
		       strerror(-rc));
		return;
	}

	while (fs_list_objs_next(&lister, &fn) > 0) {

		rc = fs_obj_hdr_read(fn, &owner, &csum, &key_in, &klen_in,
				     &size, &mtime);
		if (rc < 0) {
			free(fn);
			break;
		}

		cep = objcache_get(&chunkd_srv.actives, key_in, klen_in);
		if (!cep) {
			/* This is pretty much impossible unless OOM */
			applog(LOG_ERR, "chk: objcache_get failed");
			free(owner);
			free(csum);
			free(key_in);
			free(fn);
			break;
		}

		rc = fs_obj_do_sum(fn, klen_in, &csum_act);
		if (rc) {
			applog(LOG_INFO, "Cannot compute checksum for %s", fn);
		} else {
			if (!objcache_test_dirty(&chunkd_srv.actives, cep)) {
				if (strcmp(csum, csum_act)) {
					applog(LOG_INFO,
					       "Checksum mismatch for %s: "
					       "expected %s actual %s",
					       fn, csum, csum_act);
					fs_obj_disable(fn);
					/*
					 * FIXME Suicide the whole server if
					 * fs_obj_disable fails a few times,
					 * maybe? But what about races?
					 */
				} else {
					tls->stat_ok++;
				}
			} else {
				tls->stat_conflict++;
			}
			free(csum_act);
		}

		objcache_put(&chunkd_srv.actives, cep);
		free(owner);
		free(csum);
		free(key_in);

		free(fn);
	}
}

static void chk_dbscan(struct chk_tls *tls)
{
	TCHDB *hdb = tls->arg->hdb;
	void *kbuf;
	int klen;
	uint32_t *val_p;
	int vlen;

	tchdbiterinit(hdb);
	while ((kbuf = tchdbiternext(hdb, &klen)) != NULL) {
		if (!strcmp(kbuf, MDB_TABLE_ID)) {
			free(kbuf);
			continue;
		}
		val_p = tchdbget(hdb, kbuf, klen, &vlen);
		if (!val_p) {
			free(kbuf);
			continue;
		}
		if (vlen != sizeof(int32_t)) {
			applog(LOG_INFO, "table %s bad size %d", kbuf, vlen);
			free(val_p);
			free(kbuf);
			continue;
		}

		chk_list_objs(tls, GUINT32_FROM_LE(*val_p));

		free(val_p);
		free(kbuf);
	}
}

static void chk_thread_scan(struct chk_tls *tls)
{
	g_mutex_lock(chunkd_srv.bigmutex);
	chunkd_srv.chk_state = CHK_ST_RUNNING;
	g_mutex_unlock(chunkd_srv.bigmutex);

	tls->stat_ok = 0;
	tls->stat_conflict = 0;

	chk_dbscan(tls);
 
	g_mutex_lock(chunkd_srv.bigmutex);
	chunkd_srv.chk_done = time(NULL);
	g_mutex_unlock(chunkd_srv.bigmutex);
	if (debugging)
		applog(LOG_DEBUG, "chk: done ok %d busy %d",
		       tls->stat_ok, tls->stat_conflict);
}

static void chk_thread_command(struct chk_tls *tls)
{
	ssize_t rrc;
	unsigned char cmd;

	rrc = read(chunkd_srv.chk_pipe[0], &cmd, 1);
	if (rrc < 0) {
		applog(LOG_ERR, "pipe read error: %s", strerror(errno));
		return;
	}
	if (rrc < 1) {
		if (debugging)
			applog(LOG_DEBUG, "pipe short read, exiting\n");
		g_thread_exit(NULL);
		return;
	}

	switch (cmd) {
	case CHK_CMD_EXIT:
		g_thread_exit(NULL);
		break;
	case CHK_CMD_RESCAN:
		chk_thread_scan(tls);
		break;
	default:
		applog(LOG_ERR, "bad scan command 0x%x\n", cmd);
	}
}

static gpointer chk_thread_func(gpointer data)
{
	struct chk_tls _tls;
	struct chk_tls *tls;
	struct pollfd pfd[1];
	int tmo;
	time_t dt;
	int i;
	int rc;

	tls = &_tls;
	memset(tls, 0, sizeof(struct chk_tls));
	tls->arg = data;

	for (;;) {
		g_mutex_lock(chunkd_srv.bigmutex);
		chunkd_srv.chk_state = CHK_ST_IDLE;
		g_mutex_unlock(chunkd_srv.bigmutex);

		/*
		 * Without the randomization, all systems in a low loaded
		 * datacenter are virtually guaranteed to start checks in the
		 * same time, blow fuses and/or disrupt applications.
		 */
		dt = tls->arg->period;
		if (dt == 0) {
			tmo = -1;
		} else {
			if (dt >= 3)
				dt += rand() % (dt/3);
			if (debugging)
				applog(LOG_DEBUG, "chk: sleeping %lu s", dt);
			tmo = dt * 1000;
		}

		memset(pfd, 0, sizeof(pfd));
		pfd[0].fd = chunkd_srv.chk_pipe[0];
		pfd[0].events = POLLIN;

		rc = poll(pfd, 1, tmo);
		if (rc < 0) {
			applog(LOG_WARNING, "chk: poll error: %s",
			       strerror(errno));
			break;	/* don't flood, just die */
		}

		if (rc) {
			for (i = 0; i < ARRAY_SIZE(pfd); i++) {
				if (pfd[i].revents) {
					if (i == 0) {
						chk_thread_command(tls);
					}
				}
			}
		} else {
			chk_thread_scan(tls);
		}
	}
	return NULL;
}

/*
 * Mind that we cannot have two threads scanning the master db,
 * as long as Tokyo Cabinet embeds one and only one iterator into
 * an instance of open database with tchdbiterinit().
 */
static struct chk_arg *thread;

int chk_spawn(time_t period, TCHDB *hdb)
{
	GThread *gthread;
	struct chk_arg *arg;
	GError *error;

	arg = malloc(sizeof(struct chk_arg));
	if (!arg) {
		applog(LOG_ERR, "No core");
		return -1;
	}
	arg->period = period;
	arg->hdb = hdb;

	gthread = g_thread_create(chk_thread_func, arg, FALSE, &error);
	if (!gthread) {
		applog(LOG_ERR, "Failed to start replication thread: %s",
		       error->message);
		return -1;
	}

	// arg->gthread = gthread;
	thread = arg;

	return 0;
}

void chk_init()
{
	int rc;

	if (!chunkd_srv.chk_period) {
		if (debugging)
			applog(LOG_DEBUG, "chk: disabled by configuration");
		return;
	}

	chunkd_srv.chk_state = CHK_ST_INIT;
	rc = chk_spawn(chunkd_srv.chk_period, chunkd_srv.tbl_master);
	if (rc)
		exit(1);		/* message already logged */
}
