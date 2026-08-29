#!/usr/bin/env python3
"""
Génère le hash werkzeug du mot de passe admin pour ADMIN_PASSWORD dans .env

Usages :
  1. Via pipe (recommandé - fonctionne dans IDE, scripts, Docker) :
       echo "MonMotDePasse" | python3 generate_password_hash.py

  2. Interactif (vrai terminal uniquement) :
       python3 generate_password_hash.py

  3. Argument direct (déconseillé - reste dans l'historique bash) :
       python3 generate_password_hash.py MonMotDePasse
"""
import sys


def main():
    try:
        from werkzeug.security import generate_password_hash
    except ImportError:
        print(
            "Erreur : werkzeug non installé.\n"
            "Installez-le avec : pip install werkzeug",
            file=sys.stderr
        )
        sys.exit(1)

    password = None

    # Mode 3 : argument direct (ex: python3 generate_password_hash.py monpass)
    if len(sys.argv) > 1:
        password = sys.argv[1]
        print(
            "Avertissement : le mot de passe est visible dans l'historique du terminal.",
            file=sys.stderr
        )

    # Mode 2 : stdin non-interactif (pipe ou IDE)
    elif not sys.stdin.isatty():
        password = sys.stdin.read().strip()
        if not password:
            print("Erreur : aucun mot de passe reçu depuis stdin.", file=sys.stderr)
            sys.exit(1)

    # Mode 1 : terminal interactif (TTY)
    else:
        import getpass
        try:
            password = getpass.getpass("Entrez le nouveau mot de passe admin : ")
            confirm = getpass.getpass("Confirmez le mot de passe : ")
        except (EOFError, OSError):
            print(
                "\nErreur : pas de terminal interactif disponible.\n"
                "Utilisez l'une de ces alternatives :\n"
                "  echo 'MonMotDePasse' | python3 generate_password_hash.py\n"
                "  python3 generate_password_hash.py MonMotDePasse",
                file=sys.stderr
            )
            sys.exit(1)

        if password != confirm:
            print("Erreur : les mots de passe ne correspondent pas.", file=sys.stderr)
            sys.exit(1)

    if not password:
        print("Erreur : mot de passe vide non autorisé.", file=sys.stderr)
        sys.exit(1)

    hashed = generate_password_hash(password)

    # NE PAS doubler les `$` du hash. docker-compose interpole bien ${VAR}
    # dans les valeurs chargées via `env_file:`, ce qui corromprait un `$`
    # simple au niveau du conteneur — mais config.py recharge ensuite ce
    # même fichier en Python via load_dotenv(override=True), qui n'interpole
    # PAS les `$` et écrase la valeur Docker par le contenu brut du fichier.
    # C'est donc bien le `$` simple, littéral, qui doit être écrit ici (voir
    # api/.env.example et CLAUDE.md). Un `$$` serait lu tel quel par
    # python-dotenv et casserait le format de hash attendu par werkzeug.
    print(f"\nADMIN_PASSWORD={hashed}\n")
    print("Copiez la ligne ci-dessus dans votre api/.env", file=sys.stderr)


if __name__ == '__main__':
    main()
