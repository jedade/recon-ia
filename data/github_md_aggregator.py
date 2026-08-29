# data/github_md_aggregator.py
"""
Agrège récursivement les fichiers .md d'un dossier de dépôt GitHub public en
un seul fichier markdown, pour alimentation du RAG n8n (dossier n8n_ressource/).

Factorise la logique commune à script.py (cheat sheets OWASP), script_asvs.py
et script_wstg.py — même principe, dossier source différent.
"""
import requests


def aggregate_markdown(owner: str, repo: str, path: str, ref: str, output_file: str,
                        header_prefix: str = "") -> int:
    """
    Parcourt récursivement `path` dans `owner/repo` (branche/tag `ref`),
    concatène tous les fichiers .md trouvés dans `output_file`.

    Retourne le nombre de fichiers agrégés.
    """
    combined = ""
    count = 0

    def walk(api_path: str):
        nonlocal combined, count
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{api_path}?ref={ref}"
        response = requests.get(api_url, timeout=30)
        if response.status_code != 200:
            print(f"Erreur lors de la récupération de : {api_path} ({response.status_code})")
            return

        for item in response.json():
            if item["type"] == "dir":
                walk(item["path"])
            elif item["type"] == "file" and item["name"].endswith(".md"):
                file_response = requests.get(item["download_url"], timeout=30)
                if file_response.status_code == 200:
                    combined_title = f"{header_prefix}{item['path']}"
                    combined += f"# {combined_title}\n\n{file_response.text}\n\n---\n\n"
                    count += 1
                    print(f"Contenu ajouté pour : {item['path']}")
                else:
                    print(f"Erreur lors du téléchargement de {item['path']}")

    walk(path)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(combined)
    print(f"\n--- {count} fichiers agrégés dans {output_file} ---\n")
    return count
