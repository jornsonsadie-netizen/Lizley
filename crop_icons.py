from PIL import Image
import os

artifact_dir = r'C:\Users\ASUS\.gemini\antigravity\brain\e50b9974-9026-4519-a384-bb6d712aea93'
img_full_path = os.path.join(artifact_dir, 'media__1774083046543.jpg')
output_dir = r'C:\Users\ASUS\LizProxy\frontend\assets'

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

def process_crop(img, box, name):
    crop = img.crop(box)
    crop = crop.convert("RGBA")
    data = crop.getdata()
    
    new_data = []
    # Identify background color from a corner pixel
    bg_color = data[0]
    
    for item in data:
        # Distance to background color
        dist = sum(abs(item[i] - bg_color[i]) for i in range(3))
        if dist < 40: # Threshold for background removal
            new_data.append((255, 255, 255, 0))
        else:
            new_data.append(item)
    
    crop.putdata(new_data)
    bbox = crop.getbbox()
    if bbox:
        crop = crop.crop(bbox)
    
    crop.save(os.path.join(output_dir, name))
    print(f"Saved {name}")

try:
    with Image.open(img_full_path) as img:
        # Width 706, Height 1024. ~6 rows, ~4 cols.
        # Row height ~170. Col width ~176.
        # Home: Row 1, Col 1 (Cinnamoroll)
        process_crop(img, (40, 40, 210, 190), "home.png")
        # Create: Row 1, Col 2 (My Melody)
        process_crop(img, (240, 40, 410, 190), "create.png")
        # Chats: Row 2, Col 2 (Hello Kitty)
        process_crop(img, (240, 190, 410, 360), "chats.png")
        # Profile: Row 2, Col 4 (Kuromi)
        process_crop(img, (530, 190, 700, 360), "profile.png")
except Exception as e:
    print(f"Error: {e}")
