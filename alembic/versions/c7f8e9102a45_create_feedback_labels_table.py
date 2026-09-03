"""create feedback_labels table

Revision ID: c7f8e9102a45
Revises: b5e7a9821f03
Create Date: 2026-08-29 13:44:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c7f8e9102a45'
down_revision: Union[str, Sequence[str], None] = 'b5e7a9821f03'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'feedback_labels',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('finding_id', sa.Integer(), nullable=False),
        sa.Column('features_snapshot', sa.Text(), nullable=False),
        sa.Column('human_label', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_feedback_labels_id'), 'feedback_labels', ['id'], unique=False)
    op.create_index(op.f('ix_feedback_labels_finding_id'), 'feedback_labels', ['finding_id'], unique=False)
    op.create_index(op.f('ix_feedback_labels_human_label'), 'feedback_labels', ['human_label'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_feedback_labels_human_label'), table_name='feedback_labels')
    op.drop_index(op.f('ix_feedback_labels_finding_id'), table_name='feedback_labels')
    op.drop_index(op.f('ix_feedback_labels_id'), table_name='feedback_labels')
    op.drop_table('feedback_labels')
