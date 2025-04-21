import os
import requests
from datetime import datetime, timedelta, timezone
from app import app, db
from flask import flash
from app import Config

def refresh_spotify_token(user):
    if not user.is_token_expired():
        return user.spotify_access_token
    
    response = requests.post('https://accounts.spotify.com/api/token', data={
        'grant_type': 'refresh_token',
        'refresh token': user.spotify_refresh_token,
        'client_id': app.config['CLIENT_ID '],
        'client_secret': app.config['CLIENT_SECRET'],
    })

    if response.status_code != 200:
        flash('Failed to refresh Spotify token')
        raise Exception("Spotify token refresh failed")
    
    token_data = response.json()
    user.spotify_access_token = token_data['access_token']
    expires_in = token_data.get('expires_in', 3600)
    user.spotify_token_expires = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    db.session.commit()

    return user.spotify_access_token
        