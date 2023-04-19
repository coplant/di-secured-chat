"""add P G to chats

Revision ID: 16ab05ee9cbc
Revises: b03d982c79f3
Create Date: 2023-04-19 15:25:33.516717

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '16ab05ee9cbc'
down_revision = 'b03d982c79f3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('chatprime',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('chat_id', sa.Integer(), nullable=True),
                    sa.Column('p', sa.String(), nullable=True),
                    sa.Column('g', sa.String(), nullable=True),
                    sa.ForeignKeyConstraint(['chat_id'], ['chats.id'], ),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('chat_id')
                    )
    op.add_column('chatsusers', sa.Column('public_key', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('chatsusers', 'public_key')
    op.drop_table('chatprime')
    # ### end Alembic commands ###