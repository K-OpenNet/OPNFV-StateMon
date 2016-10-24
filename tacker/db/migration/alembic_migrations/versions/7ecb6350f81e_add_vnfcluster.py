"""add vnfcluster

Revision ID: 7ecb6350f81e
Revises: 0ae5b1ce3024
Create Date: 2016-10-22 16:45:23.118344

"""

# revision identifiers, used by Alembic.
revision = '7ecb6350f81e'
down_revision = '0ae5b1ce3024'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):

    op.create_table(
        'vnfclusters',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('vnfd_id', sa.String(length=36), nullable=False),
        sa.Column('active', sa.Integer, nullable=False),
        sa.Column('standby', sa.Integer, nullable=False),
        sa.Column('status', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB'
    )

    op.create_table(
        'vnfclustermembers',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('cluster_id', sa.String(length=36), nullable=False),
        sa.Column('index', sa.Integer, nullable=False),
        sa.Column('role', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['cluster_id'], ['vnfclusters.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB'
    )