"""add_agent_tables

Revision ID: b2c3d4e5f6a7
Revises: a547fbef3e95
Create Date: 2026-08-05 15:00:00.000000

Requirements: 14.1 – 14.8
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a547fbef3e95'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. agent_tasks ────────────────────────────────────────────────
    op.create_table(
        'agent_tasks',
        sa.Column('id',            sa.String(36),  nullable=False),
        sa.Column('user_id',       sa.String(36),  nullable=False),
        sa.Column('status',        sa.String(32),  nullable=False, server_default='pending'),
        sa.Column('description',   sa.Text(),      nullable=False),
        sa.Column('plan_json',     sa.JSON(),      nullable=True),
        sa.Column('playbook_name', sa.String(128), nullable=True),
        sa.Column('error_message', sa.Text(),      nullable=True),
        sa.Column('created_at',    sa.DateTime(),  nullable=False),
        sa.Column('updated_at',    sa.DateTime(),  nullable=False),
        sa.Column('completed_at',  sa.DateTime(),  nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_agent_tasks_user_id',    'agent_tasks', ['user_id'],             unique=False)
    op.create_index('ix_agent_tasks_status',     'agent_tasks', ['status'],              unique=False)
    op.create_index('ix_agent_tasks_created_at', 'agent_tasks', ['created_at'],          unique=False)
    op.create_index('ix_at_user_status',         'agent_tasks', ['user_id', 'status'],   unique=False)

    # ── 2. agent_executions ───────────────────────────────────────────
    op.create_table(
        'agent_executions',
        sa.Column('id',               sa.String(36), nullable=False),
        sa.Column('task_id',          sa.String(36), nullable=False),
        sa.Column('status',           sa.String(32), nullable=False, server_default='running'),
        sa.Column('steps_json',       sa.JSON(),     nullable=True),
        sa.Column('started_at',       sa.DateTime(), nullable=False),
        sa.Column('completed_at',     sa.DateTime(), nullable=True),
        sa.Column('duration_seconds', sa.Float(),    nullable=True),
        sa.Column('error_message',    sa.Text(),     nullable=True),
        sa.ForeignKeyConstraint(['task_id'], ['agent_tasks.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_agent_executions_task_id', 'agent_executions', ['task_id'], unique=False)

    # ── 3. tool_executions ────────────────────────────────────────────
    op.create_table(
        'tool_executions',
        sa.Column('id',               sa.String(36),  nullable=False),
        sa.Column('execution_id',     sa.String(36),  nullable=False),
        sa.Column('tool_name',        sa.String(128), nullable=False),
        sa.Column('category',         sa.String(64),  nullable=False),
        sa.Column('risk_level',       sa.String(16),  nullable=False),
        sa.Column('arguments_json',   sa.JSON(),      nullable=True),
        sa.Column('result_json',      sa.JSON(),      nullable=True),
        sa.Column('status',           sa.String(32),  nullable=False, server_default='running'),
        sa.Column('started_at',       sa.DateTime(),  nullable=False),
        sa.Column('completed_at',     sa.DateTime(),  nullable=True),
        sa.Column('duration_seconds', sa.Float(),     nullable=True),
        sa.Column('error_message',    sa.Text(),      nullable=True),
        sa.Column('retry_count',      sa.Integer(),   nullable=False, server_default='0'),
        sa.ForeignKeyConstraint(['execution_id'], ['agent_executions.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tool_executions_execution_id', 'tool_executions', ['execution_id'], unique=False)
    op.create_index('ix_tool_executions_tool_name',    'tool_executions', ['tool_name'],    unique=False)

    # ── 4. approvals ──────────────────────────────────────────────────
    op.create_table(
        'approvals',
        sa.Column('id',                sa.String(36),  nullable=False),
        sa.Column('task_id',           sa.String(36),  nullable=False),
        sa.Column('tool_name',         sa.String(128), nullable=False),
        sa.Column('risk_level',        sa.String(16),  nullable=False),
        sa.Column('description',       sa.Text(),      nullable=False),
        sa.Column('reason',            sa.Text(),      nullable=False),
        sa.Column('affected_resource', sa.String(512), nullable=True),
        sa.Column('estimated_impact',  sa.Text(),      nullable=True),
        sa.Column('status',            sa.String(16),  nullable=False, server_default='pending'),
        sa.Column('created_at',        sa.DateTime(),  nullable=False),
        sa.Column('decided_at',        sa.DateTime(),  nullable=True),
        sa.Column('decided_by',        sa.String(36),  nullable=True),
        sa.ForeignKeyConstraint(['task_id'], ['agent_tasks.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_approvals_task_id', 'approvals', ['task_id'], unique=False)
    op.create_index('ix_approvals_status',  'approvals', ['status'],  unique=False)

    # ── 5. scheduled_tasks ────────────────────────────────────────────
    op.create_table(
        'scheduled_tasks',
        sa.Column('id',                  sa.String(36),  nullable=False),
        sa.Column('user_id',             sa.String(36),  nullable=False),
        sa.Column('name',                sa.String(256), nullable=False),
        sa.Column('description',         sa.Text(),      nullable=True),
        sa.Column('tool_or_playbook',    sa.String(128), nullable=False),
        sa.Column('arguments_json',      sa.JSON(),      nullable=True),
        sa.Column('schedule_expression', sa.String(128), nullable=False),
        sa.Column('enabled',             sa.Boolean(),   nullable=False, server_default=sa.true()),
        sa.Column('last_run_at',         sa.DateTime(),  nullable=True),
        sa.Column('next_run_at',         sa.DateTime(),  nullable=True),
        sa.Column('created_at',          sa.DateTime(),  nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scheduled_tasks_user_id', 'scheduled_tasks', ['user_id'],            unique=False)
    op.create_index('ix_st_user_enabled',         'scheduled_tasks', ['user_id', 'enabled'], unique=False)

    # ── 6. reports ────────────────────────────────────────────────────
    op.create_table(
        'reports',
        sa.Column('id',              sa.String(36),  nullable=False),
        sa.Column('user_id',         sa.String(36),  nullable=False),
        sa.Column('period_start',    sa.DateTime(),  nullable=False),
        sa.Column('period_end',      sa.DateTime(),  nullable=False),
        sa.Column('status',          sa.String(16),  nullable=False, server_default='generating'),
        sa.Column('generated_at',    sa.DateTime(),  nullable=True),
        sa.Column('file_path',       sa.String(512), nullable=True),
        sa.Column('file_size_bytes', sa.Integer(),   nullable=True),
        sa.Column('sha256_hash',     sa.String(64),  nullable=True),
        sa.Column('error_message',   sa.Text(),      nullable=True),
        sa.Column('scope_json',      sa.JSON(),      nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_reports_user_id',    'reports', ['user_id'],                unique=False)
    op.create_index('ix_rep_user_generated', 'reports', ['user_id', 'generated_at'], unique=False)

    # ── 7. security_findings ──────────────────────────────────────────
    op.create_table(
        'security_findings',
        sa.Column('id',                sa.String(36),  nullable=False),
        sa.Column('task_id',           sa.String(36),  nullable=False),
        sa.Column('finding_type',      sa.String(64),  nullable=False),
        sa.Column('severity',          sa.String(16),  nullable=False),
        sa.Column('title',             sa.String(512), nullable=False),
        sa.Column('description',       sa.Text(),      nullable=True),
        sa.Column('affected_resource', sa.String(512), nullable=True),
        sa.Column('mitre_technique',   sa.String(64),  nullable=True),
        sa.Column('recommendation',    sa.Text(),      nullable=True),
        sa.Column('created_at',        sa.DateTime(),  nullable=False),
        sa.Column('resolved_at',       sa.DateTime(),  nullable=True),
        sa.ForeignKeyConstraint(['task_id'], ['agent_tasks.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_security_findings_task_id',      'security_findings', ['task_id'],      unique=False)
    op.create_index('ix_security_findings_finding_type', 'security_findings', ['finding_type'], unique=False)
    op.create_index('ix_security_findings_severity',     'security_findings', ['severity'],     unique=False)

    # ── 8. agent_audit_events ─────────────────────────────────────────
    op.create_table(
        'agent_audit_events',
        sa.Column('id',                       sa.String(36),   nullable=False),
        sa.Column('user_id',                  sa.String(36),   nullable=False),
        sa.Column('event_type',               sa.String(64),   nullable=False),
        sa.Column('severity',                 sa.String(16),   nullable=False, server_default='info'),
        sa.Column('request_summary',          sa.String(2048), nullable=True),
        sa.Column('plan_summary',             sa.Text(),       nullable=True),
        sa.Column('tool_name',                sa.String(128),  nullable=True),
        sa.Column('arguments_redacted_json',  sa.JSON(),       nullable=True),
        sa.Column('auth_result',              sa.String(64),   nullable=True),
        sa.Column('execution_result_summary', sa.Text(),       nullable=True),
        sa.Column('risk_level',               sa.String(16),   nullable=True),
        sa.Column('approval_status',          sa.String(16),   nullable=True),
        sa.Column('ai_conclusion',            sa.Text(),       nullable=True),
        sa.Column('created_at',               sa.DateTime(),   nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_agent_audit_events_user_id',    'agent_audit_events', ['user_id'],              unique=False)
    op.create_index('ix_agent_audit_events_event_type', 'agent_audit_events', ['event_type'],           unique=False)
    op.create_index('ix_aae_user_event',                'agent_audit_events', ['user_id', 'event_type'], unique=False)
    op.create_index('ix_aae_created',                   'agent_audit_events', ['created_at'],           unique=False)


def downgrade() -> None:
    # Drop in reverse dependency order
    op.drop_index('ix_aae_created',                   table_name='agent_audit_events')
    op.drop_index('ix_aae_user_event',                table_name='agent_audit_events')
    op.drop_index('ix_agent_audit_events_event_type', table_name='agent_audit_events')
    op.drop_index('ix_agent_audit_events_user_id',    table_name='agent_audit_events')
    op.drop_table('agent_audit_events')

    op.drop_index('ix_security_findings_severity',     table_name='security_findings')
    op.drop_index('ix_security_findings_finding_type', table_name='security_findings')
    op.drop_index('ix_security_findings_task_id',      table_name='security_findings')
    op.drop_table('security_findings')

    op.drop_index('ix_approvals_status',  table_name='approvals')
    op.drop_index('ix_approvals_task_id', table_name='approvals')
    op.drop_table('approvals')

    op.drop_index('ix_tool_executions_tool_name',    table_name='tool_executions')
    op.drop_index('ix_tool_executions_execution_id', table_name='tool_executions')
    op.drop_table('tool_executions')

    op.drop_index('ix_agent_executions_task_id', table_name='agent_executions')
    op.drop_table('agent_executions')

    op.drop_index('ix_st_user_enabled',         table_name='scheduled_tasks')
    op.drop_index('ix_scheduled_tasks_user_id', table_name='scheduled_tasks')
    op.drop_table('scheduled_tasks')

    op.drop_index('ix_rep_user_generated', table_name='reports')
    op.drop_index('ix_reports_user_id',    table_name='reports')
    op.drop_table('reports')

    op.drop_index('ix_at_user_status',         table_name='agent_tasks')
    op.drop_index('ix_agent_tasks_created_at', table_name='agent_tasks')
    op.drop_index('ix_agent_tasks_status',     table_name='agent_tasks')
    op.drop_index('ix_agent_tasks_user_id',    table_name='agent_tasks')
    op.drop_table('agent_tasks')
