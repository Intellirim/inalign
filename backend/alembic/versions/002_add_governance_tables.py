"""Add governance tables (Agent, Policy, Activity)

Revision ID: 002_governance
Revises: 001_initial
Create Date: 2024-01-20

Tables added:
- agents: Agent registration and metadata
- policies: Governance policies with JSON rules
- policy_violations: Policy violation records
- activities: Action activity logging
- agent_metrics: Aggregated agent metrics
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_governance'
down_revision = None  # Change to '001_initial' if there's a previous migration
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create agents table
    op.create_table(
        'agents',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', sa.String(length=128), nullable=False),
        sa.Column('name', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('framework', sa.String(length=64), nullable=True),
        sa.Column('version', sa.String(length=32), nullable=True),
        sa.Column('metadata_', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('status', sa.String(length=32), server_default='active', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_active_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_agents_agent_id', 'agents', ['agent_id'], unique=False)
    op.create_index('ix_agents_user_id', 'agents', ['user_id'], unique=False)
    op.create_unique_constraint('uq_agents_user_agent', 'agents', ['user_id', 'agent_id'])

    # Create policies table
    op.create_table(
        'policies',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('name', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('rules', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('priority', sa.Integer(), server_default='100', nullable=False),
        sa.Column('enabled', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('violation_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_evaluated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_policies_user_id', 'policies', ['user_id'], unique=False)
    op.create_index('ix_policies_agent_id', 'policies', ['agent_id'], unique=False)
    op.create_index('ix_policies_priority', 'policies', ['priority'], unique=False)

    # Create policy_violations table
    op.create_table(
        'policy_violations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', sa.String(length=128), nullable=False),
        sa.Column('session_id', sa.String(length=128), nullable=False),
        sa.Column('action_id', sa.String(length=128), nullable=True),
        sa.Column('violation_type', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('attempted_action', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('violated_rule', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('action_taken', sa.String(length=32), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_policy_violations_policy_id', 'policy_violations', ['policy_id'], unique=False)
    op.create_index('ix_policy_violations_agent_id', 'policy_violations', ['agent_id'], unique=False)
    op.create_index('ix_policy_violations_session_id', 'policy_violations', ['session_id'], unique=False)
    op.create_index('ix_policy_violations_created_at', 'policy_violations', ['created_at'], unique=False)

    # Create activities table
    op.create_table(
        'activities',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', sa.String(length=128), nullable=False),
        sa.Column('session_id', sa.String(length=128), nullable=False),
        sa.Column('action_id', sa.String(length=128), nullable=False),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('action_name', sa.String(length=256), nullable=False),
        sa.Column('target', sa.Text(), nullable=True),
        sa.Column('parameters', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('policy_result', sa.String(length=32), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('tokens_input', sa.Integer(), nullable=True),
        sa.Column('tokens_output', sa.Integer(), nullable=True),
        sa.Column('cost_usd', sa.Float(), nullable=True),
        sa.Column('output_preview', sa.Text(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('metadata_', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_activities_agent_id', 'activities', ['agent_id'], unique=False)
    op.create_index('ix_activities_session_id', 'activities', ['session_id'], unique=False)
    op.create_index('ix_activities_action_id', 'activities', ['action_id'], unique=False)
    op.create_index('ix_activities_action_type', 'activities', ['action_type'], unique=False)
    op.create_index('ix_activities_created_at', 'activities', ['created_at'], unique=False)

    # Create agent_metrics table
    op.create_table(
        'agent_metrics',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', sa.String(length=128), nullable=False),
        sa.Column('period_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('period_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('granularity', sa.String(length=16), nullable=False),
        sa.Column('total_sessions', sa.Integer(), server_default='0', nullable=False),
        sa.Column('total_actions', sa.Integer(), server_default='0', nullable=False),
        sa.Column('successful_actions', sa.Integer(), server_default='0', nullable=False),
        sa.Column('failed_actions', sa.Integer(), server_default='0', nullable=False),
        sa.Column('blocked_actions', sa.Integer(), server_default='0', nullable=False),
        sa.Column('total_threats', sa.Integer(), server_default='0', nullable=False),
        sa.Column('policy_violations', sa.Integer(), server_default='0', nullable=False),
        sa.Column('avg_risk_score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('total_tokens_input', sa.Integer(), server_default='0', nullable=False),
        sa.Column('total_tokens_output', sa.Integer(), server_default='0', nullable=False),
        sa.Column('total_cost_usd', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('avg_latency_ms', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_agent_metrics_agent_id', 'agent_metrics', ['agent_id'], unique=False)
    op.create_index('ix_agent_metrics_period', 'agent_metrics', ['period_start', 'period_end'], unique=False)
    op.create_unique_constraint(
        'uq_agent_metrics_agent_period',
        'agent_metrics',
        ['agent_id', 'period_start', 'granularity']
    )


def downgrade() -> None:
    op.drop_table('agent_metrics')
    op.drop_table('activities')
    op.drop_table('policy_violations')
    op.drop_table('policies')
    op.drop_table('agents')
