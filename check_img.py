from PIL import Image
import os

img_path = r'C:\Users\ASUS\LizProxy\media__1774083046543.jpg'
# I need to find where the media file actually is. 
# The list_dir showed it in the artifact directory.
artifact_dir = r'C:\Users\ASUS\.gemini\antigravity\brain\e50b9974-9026-4519-a384-bb6d712aea93'
img_full_path = os.path.join(artifact_dir, 'media__1774083046543.jpg')

try:
    with Image.open(img_full_path) as img:
        print(f"Dimensions: {img.size}")
except Exception as e:
    print(f"Error: {e}")
