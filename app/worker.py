"""Background workers. Jobs live in the database, so a restart picks up where it left off.

Run inside the web process (default) or as a separate process with `python -m app.worker`
(set VT_EMBEDDED_WORKER=false on the web process in that case)."""
import logging
import threading
import time

from sqlalchemy import select, update

from .analyzer import JobRunner
from .config import settings
from .db import AnalysisJob, SessionLocal, init_db, utcnow

log = logging.getLogger(__name__)
_stop = threading.Event()


def _claim_next() -> int | None:
    with SessionLocal() as db:
        job_id = db.scalar(select(AnalysisJob.id).where(AnalysisJob.status == "queued")
                           .order_by(AnalysisJob.id).limit(1))
        if job_id is None:
            return None
        # Atomic claim: only one worker wins the update.
        res = db.execute(update(AnalysisJob).where(AnalysisJob.id == job_id, AnalysisJob.status == "queued")
                         .values(status="running", started_at=utcnow(), progress="Starting"))
        db.commit()
        return job_id if res.rowcount == 1 else None


def _loop(n: int):
    while not _stop.is_set():
        job_id = _claim_next()
        if job_id is None:
            _stop.wait(2)
            continue
        log.info("Worker %s running job %s", n, job_id)
        try:
            JobRunner(job_id).run()
        except Exception as exc:  # noqa: BLE001 - e.g. missing token
            log.exception("Job %s could not start", job_id)
            with SessionLocal() as db:
                job = db.get(AnalysisJob, job_id)
                job.status, job.error, job.finished_at = "failed", str(exc), utcnow()
                db.commit()


def recover_interrupted():
    """Jobs left 'running' by a crash, restart or upgrade go back to the queue; they resume where they stopped."""
    with SessionLocal() as db:
        db.execute(update(AnalysisJob).where(AnalysisJob.status == "running")
                   .values(status="queued", progress="Interrupted by a restart; resumes where it stopped"))
        db.commit()


def start(threads: int | None = None) -> list[threading.Thread]:
    recover_interrupted()
    workers = []
    for n in range(threads or settings.worker_threads):
        t = threading.Thread(target=_loop, args=(n,), name=f"vt-worker-{n}", daemon=True)
        t.start()
        workers.append(t)
    return workers


def stop():
    _stop.set()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    init_db()
    start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop()
