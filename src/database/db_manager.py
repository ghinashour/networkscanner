"""
Database manager for the AI Network Scanner.
Handles database connections and initialization.
"""

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.engine import Engine

from src.config import Config
from src.database.models import Base
from src.utils.logger import logger


class DatabaseManager:
    """Manage SQLAlchemy engine and database sessions."""

    def __init__(self, database_url: str | None = None):

        self.database_url = database_url or Config.DATABASE_URL

        Config.ensure_directories()

        self.engine: Engine = create_engine(
            self.database_url,
            echo=Config.DEBUG,
            connect_args={"check_same_thread": False},
        )

        self.SessionLocal = sessionmaker(
            bind=self.engine,
            autoflush=False,
            autocommit=False,
        )

        self.init_database()

    # --------------------------------------------------
    # Database Initialization
    # --------------------------------------------------

    def init_database(self) -> None:
        """Create all database tables."""

        try:

            Base.metadata.create_all(bind=self.engine)

            inspector = inspect(self.engine)

            tables = inspector.get_table_names()

            logger.info(
                "Database initialized successfully."
            )

            logger.info(
                f"Available tables: {', '.join(tables)}"
            )

        except SQLAlchemyError as e:

            logger.exception("Database initialization failed.")

            raise

    # --------------------------------------------------
    # Session
    # --------------------------------------------------

    def get_session(self) -> Session:
        """Return a new database session."""
        return self.SessionLocal()

    # --------------------------------------------------
    # Cleanup
    # --------------------------------------------------

    def close(self) -> None:
        """Dispose the database engine."""

        self.engine.dispose()

        logger.info("Database connection closed.")

    # --------------------------------------------------
    # Table Management
    # --------------------------------------------------

    def drop_all_tables(self) -> None:
        """Drop every table."""

        try:

            Base.metadata.drop_all(bind=self.engine)

            logger.warning("All database tables dropped.")

        except SQLAlchemyError:

            logger.exception("Failed to drop tables.")

            raise

    def recreate_database(self) -> None:
        """Recreate the database."""

        self.drop_all_tables()

        self.init_database()

        logger.info("Database recreated.")

    # --------------------------------------------------
    # Queries
    # --------------------------------------------------

    def get_table_count(self, table_name: str) -> int:
        """Return number of rows inside a table."""

        try:

            with self.get_session() as session:

                result = session.execute(
                    text(f"SELECT COUNT(*) FROM {table_name}")
                )

                count = result.scalar_one()

                return int(count)

        except SQLAlchemyError:

            logger.exception(
                f"Failed counting rows in '{table_name}'."
            )

            return 0

    def execute_raw_query(self, query: str):
        """Execute a raw SQL query."""

        try:

            with self.get_session() as session:

                result = session.execute(text(query))

                session.commit()

                return result

        except SQLAlchemyError:

            logger.exception("Raw SQL execution failed.")

            raise


# Global database manager
db_manager = DatabaseManager()