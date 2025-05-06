from datetime import datetime, timezone, timedelta
from flask import render_template, flash, redirect, url_for, request, current_app, session, jsonify
from flask_login import login_user, logout_user, current_user, login_required
import sqlalchemy as sa, os
from app import app, db
from app.forms import EditProfileForm, EmptyForm, PostForm, RepostForm
from app.models import User, Post
from app.utils import save_profile_picture
from app.spotify import refresh_spotify_token
from urllib.parse import urlencode
import requests
import secrets


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    form = PostForm()
    if form.validate_on_submit():
        spotify_item_type = form.spotify_item_type.data.strip()
        spotify_item_id = form.spotify_item_id.data.strip()

        post = Post(body=form.post.data, author=current_user, spotify_item_id=spotify_item_id, spotify_item_type=spotify_item_type)
        db.session.add(post)
        db.session.commit()
        flash('Your post is now live!')
        return redirect(url_for('index'))
    page = request.args.get('page', 1, type=int)
    posts = db.paginate(current_user.following_posts(), page=page,
                        per_page=app.config['POSTS_PER_PAGE'], error_out=False)
    next_url = url_for('index', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('index', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('index.html', title='Home', form=form,
                           posts=posts.items, next_url=next_url,
                           prev_url=prev_url)


@app.route('/explore')
@login_required
def explore():
    page = request.args.get('page', 1, type=int)
    query = sa.select(Post).order_by(Post.timestamp.desc())
    posts = db.paginate(query, page=page,per_page=app.config['POSTS_PER_PAGE'], error_out=False)
    next_url = url_for('explore', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('explore', page=posts.prev_num) \
        if posts.has_prev else None
    form = EmptyForm()
    return render_template('explore.html', title='Explore', posts=posts.items,
                           next_url=next_url, prev_url=prev_url, form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    return render_template('login.html', title='Sign In')


@app.route('/spotify_login')
def spotify_login():
    state = secrets.token_urlsafe(16)
    session['spotify_auth_state'] = state

    auth_url = (
        "https://accounts.spotify.com/authorize"
        f"?client_id={app.config['SPOTIFY_CLIENT_ID']}"
        f"&response_type=code"
        f"&redirect_uri={app.config['REDIRECT_URI']}"
        f"&scope=user-read-email user-read-private"
        f"&state={state}"
        f"&show_dialog=true"
    )

    return redirect(auth_url)
    


@app.route('/logout')
def logout():
    logout_user()
    session.pop('spotify_auth_state', None)
    return redirect(url_for('index'))

def spotify_login():
    state = secrets.token_urlsafe(16)
    session['spotify_auth_state'] = state
    query_params = urlencode({
        'client_id': app.config['SPOTIFY_CLIENT_ID'],
        'response_type': 'code',
        'redirect_uri': app.config['REDIRECT_URI'],
        'scope': app.config['SCOPE'],
        'state': state
    })
    return redirect(f"{app.config['SPOTIFY_AUTH_URL']}?{query_params}")
    

@app.route('/callback', methods=['GET','POST'])
def callback():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if 'error' in request.args:
        flash("Spotify authorization failed.")
        return redirect(url_for('login'))

    code = request.args.get('code')
    state = request.args.get('state')

    if state != session.get('spotify_auth_state'):
        flash("State mismatch. Possible CSRF attack.")
        return redirect(url_for('login'))
    
    # Exchange code for token
    token_response = requests.post(app.config['SPOTIFY_TOKEN_URL'], data={
    'grant_type': 'authorization_code',
    'code': code,
    'redirect_uri': app.config['REDIRECT_URI'],
    'client_id': app.config['SPOTIFY_CLIENT_ID'],
    'client_secret': app.config['CLIENT_SECRET']  
    })

    print("Status Code:", token_response.status_code)
    print("Response Text:", token_response.text)

    if token_response.status_code != 200:
        flash("Failed to authenticate with Spotify.")
        return redirect(url_for('login'))

    try:
        token_data = token_response.json()
    except requests.exceptions.JSONDecodeError:
        flash("Invalid response from Spotify during token exchange.")
        return redirect(url_for('login'))
    access_token = token_data.get('access_token')
    refresh_token = token_data.get('refresh_token')
    expires_in = token_data.get('expires_in')

    # Get Spotify user profile
    headers = {'Authorization': f'Bearer {access_token}'}
    user_profile = requests.get(f"{app.config['SPOTIFY_API_BASE_URL']}/me", headers=headers).json()

    spotify_id = user_profile['id']
    display_name = user_profile.get('display_name', f"spotify_user_{spotify_id}")
    email = user_profile['email']

    # Lookup or create user
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(username=display_name or spotify_id, email=email)
        db.session.add(user)

    # Save Spotify credentials
    user.spotify_access_token = access_token
    user.spotify_refresh_token = refresh_token
    user.spotify_token_expires = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    db.session.commit()

    login_user(user)
    flash("Successfully signed in with Spotify!")
    return redirect(url_for('index'))

@app.route('/user/<username>')
@login_required
def user(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    page = request.args.get('page', 1, type=int)
    query = user.posts.select().order_by(Post.timestamp.desc())
    posts = db.paginate(query, page=page,
                        per_page=app.config['POSTS_PER_PAGE'],
                        error_out=False)
    next_url = url_for('user', username=user.username, page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('user', username=user.username, page=posts.prev_num) \
        if posts.has_prev else None
    form = EmptyForm()
    return render_template('user.html', user=user, posts=posts.items, next_url=next_url, prev_url=prev_url, form=form)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        if form.profile_image.data:
            delete_profile_picture()
            #Saves pfp if one was uploaded
            picture_file = save_profile_picture(form.profile_image.data)
            current_user.profile_image = picture_file
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('user', username=current_user.username))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',form=form)

@app.route('/delete_profile_picture', methods=['POST'])
@login_required
def delete_profile_picture():
    if current_user.profile_image and current_user.profile_image != 'default.jpg':
        picture_path = os.path.join(current_app.root_path, 'static/profile_pics', current_user.profile_image)
        if os.path.exists(picture_path):
            os.remove(picture_path)

        current_user.profile_image = 'default.jpg'
        db.session.commit()
        flash('Your profile picture has been removed.')
    else:
        flash('You are already using the default avatar.')

    return redirect(url_for('edit_profile'))

@app.route('/follow/<username>', methods=['POST'])
@login_required
def follow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == username))
        if user is None:
            flash(f'User {username} not found.')
            return redirect(url_for('index'))
        if user == current_user:
            flash('You cannot follow yourself!')
            return redirect(url_for('user', username=username))
        current_user.follow(user)
        db.session.commit()
        flash(f'You are following {username}!')
        return redirect(url_for('user', username=username))
    else:
        return redirect(url_for('index'))


@app.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == username))
        if user is None:
            flash(f'User {username} not found.')
            return redirect(url_for('index'))
        if user == current_user:
            flash('You cannot unfollow yourself!')
            return redirect(url_for('user', username=username))
        current_user.unfollow(user)
        db.session.commit()
        flash(f'You are not following {username}.')
        return redirect(url_for('user', username=username))
    else:
        return redirect(url_for('index'))

@app.route('/reset_db')
def reset_db():
   flash("Resetting database: deleting old data")
   # clear all data from all tables
   meta = db.metadata
   for table in reversed(meta.sorted_tables):
       print('Clear table {}'.format(table))
       db.session.execute(table.delete())
       # delete profile picture from the profile picture folder when db is reset
       delete_profile_picture()
   db.session.commit()

   return redirect(url_for('index'))

@app.route('/spotify-search')
@login_required
def spotify_search():
    query = request.args.get('q')
    if not query:
        return jsonify(results=[]), 400  # 400 = Bad Request
    
    # Get a fresh token if needed
    access_token = current_user.spotify_access_token
    if current_user.is_token_expired():
        access_token = refresh_spotify_token(current_user)

    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    params = {
        'q': query,
        'type': 'track,album,artist',
        'limit': 5
    }

    response = requests.get('https://api.spotify.com/v1/search', headers=headers, params=params)

    if response.status_code != 200:
        return jsonify(results=[]), 502
    
    data = response.json()
    results = []

    for t in data.get('tracks', {}).get('items', []):
        results.append({'id': t['id'], 'name': t['name'], 'type': 'track'})
    for a in data.get('albums', {}).get('items', []):
        results.append({'id': a['id'], 'name': a['name'], 'type': 'album'})
    for ar in data.get('artists', {}).get('items', []):
        results.append({'id': ar['id'], 'name': ar['name'], 'type': 'artist'})
    
    return jsonify(results=results)

@app.route('/repost/<int:post_id>', methods=['POST'])
@login_required
def repost(post_id):
    original_post = db.session.get(Post, post_id)
    form = RepostForm()
    if form.validate_on_submit():
        repost = Post(
            body=form.body.data,
            author=current_user,
            is_repost=True,
            original_post=original_post
        )
        db.session.add(repost)
        db.session.commit()
        flash('Post reposted!')
    return redirect(url_for('index'))