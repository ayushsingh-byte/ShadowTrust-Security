from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import text

DATABASE_URL = "sqlite+aiosqlite:///./ingestion.db"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # --- Migration: add requested_clearance_level if missing ---
        try:
            result = await conn.execute(text("PRAGMA table_info(users)"))
            columns = [row[1] for row in result.fetchall()]
            if "requested_clearance_level" not in columns:
                await conn.execute(text("ALTER TABLE users ADD COLUMN requested_clearance_level INTEGER"))
                print("[MIGRATION] Added 'requested_clearance_level' column to users table.")
        except Exception as e:
            print(f"[MIGRATION] Column check skipped: {e}")

    # --- Seed default admin user ---
    await _seed_admin()

async def _seed_admin():
    """Create a default SUPER_ADMIN user if none exists."""
    from app.models.all_models import User
    from sqlalchemy.future import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.role == "SUPER_ADMIN"))
        existing_admin = result.scalars().first()

        if not existing_admin:
            import bcrypt
            import uuid
            password = "admin"
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            admin = User(
                id=str(uuid.uuid4()),
                username="admin",
                email="admin@gmail.com",
                password_hash=hashed,
                first_name="System",
                last_name="Admin",
                department="Administration",
                role="SUPER_ADMIN",
                clearance_level=3,
                requested_clearance_level=3,
                status="ACTIVE"
            )
            session.add(admin)
            await session.commit()
            print("[SEED] Default admin user created: admin@gmail.com / admin")
        else:
            print(f"[SEED] Admin user already exists: {existing_admin.email}")
