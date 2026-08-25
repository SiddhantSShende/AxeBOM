/**
 * Threaded comment rail for a report.
 *
 * ⚠ A DELETED COMMENT WITH LIVE REPLIES NEVER DISAPPEARS. The server already
 * rewrites its body to "[deleted]" and marks `deleted: true`; this component
 * still renders that row (dimmed, no edit/delete controls) so its replies
 * keep a parent to indent under. Hiding the row would either orphan the
 * replies visually or force removing them too, which would delete content
 * their own authors never asked to delete.
 *
 * ⚠ ONLY THE COMMENT'S OWN AUTHOR SEES EDIT/DELETE. The API enforces this
 * for real (403 PERM_COMMENT_NOT_OWNER) — hiding the controls here is a
 * convenience, not the boundary.
 */

import { useState } from 'react';
import { useAuth } from '../lib/useAuth';
import {
  useComments,
  useCreateComment,
  useDeleteComment,
  useUpdateComment,
  type Comment,
} from '../lib/comments';
import { ErrorState, SkeletonRows } from './States';

const MAX_DEPTH = 5;

export function CommentRail({ reportId }: { reportId: string }) {
  const { data, isPending, isError, error } = useComments(reportId);
  const create = useCreateComment(reportId);
  const [draft, setDraft] = useState('');

  if (isPending) return <SkeletonRows rows={3} columns={1} />;
  if (isError) return <ErrorState error={error} action="load comments" />;

  const comments = data?.comments ?? [];
  const roots = comments.filter((c) => !c.parent_id);
  const byParent = new Map<string, Comment[]>();
  for (const c of comments) {
    if (!c.parent_id) continue;
    byParent.set(c.parent_id, [...(byParent.get(c.parent_id) ?? []), c]);
  }

  return (
    <section className="panel" aria-labelledby="comments-heading">
      <h2 id="comments-heading">Comments</h2>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!draft.trim()) return;
          create.mutate({ body: draft }, { onSuccess: () => setDraft('') });
        }}
      >
        <label className="field">
          <span>Add a comment</span>
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={3}
            placeholder="Discuss this report, or @mention a teammate"
          />
        </label>
        <div className="step-actions">
          <button type="submit" className="btn btn-primary" disabled={create.isPending || !draft.trim()}>
            Comment
          </button>
        </div>
        {create.isError && <p className="status status-down">{create.error.message}</p>}
      </form>

      {roots.length === 0 ? (
        <p className="field-hint">No comments yet.</p>
      ) : (
        <ul style={{ listStyle: 'none', padding: 0 }}>
          {roots.map((c) => (
            <CommentNode key={c.id} comment={c} byParent={byParent} reportId={reportId} />
          ))}
        </ul>
      )}
    </section>
  );
}

function CommentNode({
  comment,
  byParent,
  reportId,
}: {
  comment: Comment;
  byParent: Map<string, Comment[]>;
  reportId: string;
}) {
  const { user } = useAuth();
  const update = useUpdateComment(reportId);
  const del = useDeleteComment(reportId);
  const [editing, setEditing] = useState(false);
  const [replying, setReplying] = useState(false);
  const [editDraft, setEditDraft] = useState(comment.body);
  const [replyDraft, setReplyDraft] = useState('');
  const create = useCreateComment(reportId);

  const isOwner = !comment.deleted && user?.profile.sub === comment.user_id;
  const replies = byParent.get(comment.id) ?? [];

  return (
    <li style={{ marginLeft: comment.depth * 24 }}>
      <div className={comment.deleted ? 'field-hint' : undefined}>
        <p>
          {comment.deleted ? (
            <em>{comment.body}</em>
          ) : editing ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!editDraft.trim()) return;
                update.mutate(
                  { id: comment.id, body: editDraft },
                  { onSuccess: () => setEditing(false) },
                );
              }}
            >
              <textarea value={editDraft} onChange={(e) => setEditDraft(e.target.value)} rows={2} />
              <div className="step-actions">
                <button type="submit" className="btn btn-primary" disabled={update.isPending}>
                  Save
                </button>
                <button type="button" className="btn" onClick={() => setEditing(false)}>
                  Cancel
                </button>
              </div>
            </form>
          ) : (
            comment.body
          )}
        </p>
        {!editing && (
          <p className="field-hint">
            {new Date(comment.created_at).toLocaleString()}
            {comment.edited && ' (edited)'}
            {!comment.deleted && comment.depth < MAX_DEPTH && (
              <>
                {' · '}
                <button type="button" className="btn" onClick={() => setReplying((v) => !v)}>
                  Reply
                </button>
              </>
            )}
            {isOwner && (
              <>
                {' · '}
                <button type="button" className="btn" onClick={() => setEditing(true)}>
                  Edit
                </button>
                {' · '}
                <button
                  type="button"
                  className="btn"
                  onClick={() => {
                    if (confirm('Delete this comment?')) del.mutate(comment.id);
                  }}
                >
                  Delete
                </button>
              </>
            )}
          </p>
        )}
      </div>

      {replying && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!replyDraft.trim()) return;
            create.mutate(
              { parentId: comment.id, body: replyDraft },
              { onSuccess: () => { setReplyDraft(''); setReplying(false); } },
            );
          }}
        >
          <textarea value={replyDraft} onChange={(e) => setReplyDraft(e.target.value)} rows={2} />
          <div className="step-actions">
            <button type="submit" className="btn btn-primary" disabled={create.isPending}>
              Reply
            </button>
            <button type="button" className="btn" onClick={() => setReplying(false)}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {replies.length > 0 && (
        <ul style={{ listStyle: 'none', padding: 0 }}>
          {replies.map((r) => (
            <CommentNode key={r.id} comment={r} byParent={byParent} reportId={reportId} />
          ))}
        </ul>
      )}
    </li>
  );
}
