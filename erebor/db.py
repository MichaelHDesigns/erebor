from functools import partial
from asyncpg import create_pool
from asyncpg import exceptions
from sanic import Blueprint

db_bp = Blueprint('db')


async def _pg_fetch(pg_pool, sql, *args, **kwargs):
    async with pg_pool.acquire() as connection:
        return await connection.fetch(sql, *args, **kwargs)


async def _pg_fetchrow(pg_pool, sql, *args, **kwargs):
    async with pg_pool.acquire() as connection:
        return await connection.fetchrow(sql, *args, **kwargs)


async def _pg_execute(pg_pool, sql, *args, **kwargs):
    async with pg_pool.acquire() as connection:
        return await connection.execute(sql, *args, **kwargs)


async def _pg_close(pg_pool, *args, **kwargs):
    return await pg_pool.close()


class PG:
    def __init__(self, pg_pool):
        self.fetch = partial(_pg_fetch, pg_pool)
        self.fetchrow = partial(_pg_fetchrow, pg_pool)
        self.execute = partial(_pg_execute, pg_pool)
        self.close = partial(_pg_close, pg_pool)


@db_bp.listener('before_server_start')
async def init_pg(app, loop):
    try:
        app.pg_pool = await create_pool(
            **app.db,
            loop=loop,
            max_size=10,
        )
        app.pg = PG(app.pg_pool)
    except exceptions.TooManyConnectionsError:
        print("Too many connections")
    except Exception as e:
        print("Error: " + e)


@db_bp.listener('after_server_stop')
async def close_pg(app, loop):
    await app.pg.close()
