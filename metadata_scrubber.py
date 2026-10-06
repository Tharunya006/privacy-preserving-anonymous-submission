from PIL import Image


def remove_metadata(input_path, output_path):
    """
    Removes metadata from an image and saves a clean copy.
    """

    image = Image.open(input_path)

    # Load the actual pixel data
    image.load()

    # Create a new image containing only the pixel data.
    # This removes EXIF and other embedded metadata.
    clean_image = Image.new(image.mode, image.size)
    clean_image.putdata(list(image.getdata()))

    # JPEG images cannot be saved in RGBA mode.
    if image.format == "JPEG" and clean_image.mode in ("RGBA", "LA"):
        clean_image = clean_image.convert("RGB")

    # Save the clean image without carrying over the original metadata.
    clean_image.save(output_path)

    return output_path


if __name__ == "__main__":
    print("Metadata scrubber is ready.")