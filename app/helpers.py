import csv
import os

def generate_csv(app, updates, filename):
    csv_filepath = os.path.join(app.config['CSV_DOWNLOAD_FOLDER'], filename)

    with open(csv_filepath, 'w', newline='') as csvfile:
        fieldnames = updates[0].keys()
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for update in updates:
            writer.writerow(update)

    return csv_filepath

