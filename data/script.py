import requests
import os

# URL de l'API GitHub pour lister le contenu du répertoire
api_url = "https://api.github.com/repos/OWASP/CheatSheetSeries/contents/cheatsheets?ref=master"

# Initialiser une variable pour stocker le contenu combiné
combined_cheatsheet_content = ""
cheatsheet_count = 0

# Récupérer la liste des fichiers
response = requests.get(api_url)
if response.status_code == 200:
    files = response.json()

    for file in files:
        # Vérifier que l'élément est un fichier (pas un sous-répertoire) et qu'il se termine par .md
        if file['type'] == 'file' and file['name'].endswith('.md'):
            # Construire l'URL raw pour chaque fichier
            raw_url = f"https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/{file['path']}"
            # Récupérer le contenu du fichier
            file_response = requests.get(raw_url)
            if file_response.status_code == 200:
                # Ajouter le contenu au contenu combiné, avec un séparateur
                combined_cheatsheet_content += f"# {file['name']}\n\n"
                combined_cheatsheet_content += file_response.text
                combined_cheatsheet_content += "\n\n---\n\n" # Séparateur entre les cheat sheets
                cheatsheet_count += 1
                print(f"Contenu ajouté pour : {file['name']}")
            else:
                print(f"Erreur lors du téléchargement de {file['name']}")
else:
    print("Erreur lors de la récupération de la liste des fichiers")

# Afficher ou utiliser la variable combined_cheatsheet_content
print(f"\n--- Contenu combiné de {cheatsheet_count} cheatsheets ---\n")
# Vous pouvez maintenant utiliser la variable combined_cheatsheet_content
# Par exemple, l'afficher entièrement (peut être très long) ou l'enregistrer dans un fichier unique.
# print(combined_cheatsheet_content)

# Optionnel : enregistrer le contenu combiné dans un fichier unique
output_combined_file = "combined_owasp_cheatsheets.md"
with open(output_combined_file, "w", encoding="utf-8") as f:
    f.write(combined_cheatsheet_content)
print(f"\nContenu combiné enregistré dans : {output_combined_file}")
