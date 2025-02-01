import argparse
import json
import hashlib

class MixpanelEventsMaskHandler:
    def __init__(self, args):
        self.secret_key = args.key
        self.file_name = args.file_name

    def mask_value(self, value):
        """mask a value consistently using a hash function and a secret key."""
        return hashlib.sha256(f"{self.secret_key}{value}".encode()).hexdigest()

    def mask_data(self, events, fields_to_mask):
        """mask specified fields in a list of JSON objects."""
        mapping = {}

        for item in events:
            for field in fields_to_mask:
                if field in item["properties"]:
                    original_value = item["properties"][field]
                    
                    if original_value in mapping:
                        item["properties"][field] = mapping[original_value]
                    else:
                        masked_value = self.mask_value(original_value)
                        mapping[original_value] = masked_value
                        item["properties"][field] = masked_value

        return events
    
    def run(self):
        events = []

        print(f"Iniciando leitura dos eventos {self.file_name}. . .")

        with open(f"{self.file_name}.private.txt", "r") as f:
            for line in f:
                try:
                    json_obj = json.loads(line.replace('""', '"').strip())
                    events.append(json_obj)
                except json.JSONDecodeError:
                    print(f"Line could not be parsed as JSON: {line.strip()}")

        print("Arquivo fonte lido, foram computados", len(events), "eventos")

        print("Iniciando anonimização dos ids . . .")

        fields_to_mask = [
            "$user_id",
            "$device_id",
            "$distinct_id_before_identity",
            "$insert_id",
            "distinct_id",
        ]

        masked_data = self.mask_data(events, fields_to_mask)

        with open(f"{self.file_name}.masked.json", "w") as f:
            json.dump(masked_data, f, indent=4)


        print("Arquivo destino escrito, dados anonimizados com sucesso")
        print("Finalizando . . .")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script de anonimização dos ids de usuários nos eventos do mixpanel"
    )
    parser.add_argument("--key", default="")
    parser.add_argument("--file-name", default="events")
    args = parser.parse_args()

    handler = MixpanelEventsMaskHandler(args)
    handler.run()
