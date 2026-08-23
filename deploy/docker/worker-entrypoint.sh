#!/bin/sh
# EncoreBOM worker entrypoint.
#
# With no arguments, start the family named by ENCOREBOM_WORKER_FAMILY.
# With arguments, run those instead.
#
# The second half matters more than it looks. The previous form was
#     ENTRYPOINT ["/bin/sh", "-c", "exec python -m workers.${FAMILY}.runner"]
# and `sh -c` assigns any appended arguments to $0, $1, ... rather than
# executing them. So `docker compose run sbom-worker python whatever.py`
# silently ignored the command and started the idle worker loop instead — the
# container looked alive and did nothing anyone asked for. Operator commands
# (dbsync, dbstatus, the engine smoke run) all arrive this way.
set -e

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

: "${ENCOREBOM_WORKER_FAMILY:=sbom}"

case "$ENCOREBOM_WORKER_FAMILY" in
    sbom|cbom|aibom|qbom|hbom) ;;
    *)
        echo "unknown ENCOREBOM_WORKER_FAMILY: '$ENCOREBOM_WORKER_FAMILY'" >&2
        echo "expected one of: sbom cbom aibom qbom hbom" >&2
        exit 64
        ;;
esac

exec python -m "workers.${ENCOREBOM_WORKER_FAMILY}.runner"
