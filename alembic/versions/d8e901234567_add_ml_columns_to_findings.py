"""add ml_confidence and ml_predicted_label to findings

Revision ID: d8e901234567
Revises: c7f8e9102a45
Create Date: 2026-08-29 14:16:35.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd8e901234567'
down_revision: Union[str, Sequence[str], None] = 'c7f8e9102a45'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('findings', sa.Column('ml_confidence', sa.Float(), nullable=True))
    op.add_column('findings', sa.Column('ml_predicted_label', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('findings', 'ml_predicted_label')
    op.drop_column('findings', 'ml_confidence')
