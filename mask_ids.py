import csv
import hashlib
import argparse

class BetaTestersIdsMaskHandler:
    def __init__(self, args):
        self.secret_key = args.key
        self.source_file = args.source_file
        self.output_file = args.output_file

    def mask_value(self, value):
        return hashlib.sha256(f"{self.secret_key}{value}".encode()).hexdigest()

    def run(self):
        print("Iniciando leitura dos ids originais dos usuários . . .")
        private_users_ids = []

        with open(self.source_file, mode='r') as file:
            reader = csv.reader(file)
            for row in reader:
                private_users_ids.append(row[0])

        print("Arquivo fonte lido, foram computados", len(private_users_ids), "ids")

        print("Iniciando anonimização dos ids . . .")

        masked_users_ids = []

        with open(self.output_file, mode='w') as file:
            writer = csv.writer(file)
            for user_id in private_users_ids:
                masked_id = self.mask_value(user_id)
                masked_users_ids.append(masked_id)
                writer.writerow([masked_id])

        print("Arquivo destino escrito, foram anonimizados", len(masked_users_ids), "ids")
        print("Finalizando . . .")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script de anonimização dos ids de usuários beta"
    )
    parser.add_argument("--key", default="")
    parser.add_argument("--source-file", default="beta_testers_ids.private.txt")
    parser.add_argument("--output-file", default="beta_testers_ids.masked.txt")
    args = parser.parse_args()

    handler = BetaTestersIdsMaskHandler(args)
    handler.run()
