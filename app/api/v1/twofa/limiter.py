from datetime import datetime, timedelta

from fastapi import HTTPException

MAX_ATTEMPTS = 5 # Máximo de intentos antes de bloqueo
LOCK_TIME_MINUTES = 5 # Tiempo de bloqueo en minutos


def check_attempts(user):
    # Está bloqueado por intentos?
    if user.two_fa_locked_until and user.two_fa_locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=429,
            detail=f"Demasiados intentos. Intenta después de {user.two_fa_locked_until}."
        )


def register_failed_attempt(user, db):
    user.two_fa_attempts += 1

    if user.two_fa_attempts >= MAX_ATTEMPTS:
        user.two_fa_locked_until = datetime.utcnow() + timedelta(minutes=LOCK_TIME_MINUTES)
        user.two_fa_attempts = 0  # reset
        db.commit()
        return

    db.commit()


def reset_attempts(user, db):
    user.two_fa_attempts = 0
    user.two_fa_locked_until = None
    db.commit()
