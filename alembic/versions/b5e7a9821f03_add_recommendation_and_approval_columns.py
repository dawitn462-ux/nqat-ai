"""add recommendation and approval columns to findings

Revision ID: b5e7a9821f03
Revises: da6fc8b19d98
Create Date: 2026-08-29 12:44:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b5e7a9821f03'
down_revision: Union[str, Sequence[str], None] = 'da6fc8b19d98'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('findings', sa.Column('recommendation', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('config_snippet', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('findings', sa.Column('approved_by', sa.String(length=255), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('findings', 'approved_by')
    op.drop_column('findings', 'approved_at')
    op.drop_column('findings', 'config_snippet')
    op.drop_column('findings', 'recommendation')
