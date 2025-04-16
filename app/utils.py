import os
import uuid
from PIL import Image
from flask import current_app

def save_profile_picture(form_picture):
    # Make a unique filename
    filename = f"{uuid.uuid4().hex}{os.path.splitext(form_picture.filename)[1]}"
    # Build full path to save it
    path = os.path.join(current_app.root_path, 'static/profile_pics', filename)

    # Open and resize image to 256x256 (keep aspect ratio)
    image = Image.open(form_picture)
    image.thumbnail((256, 256))
    image.save(path)

    return filename