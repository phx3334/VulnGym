import json, os

ids = {'entry-00099','entry-00100','entry-00103','entry-00176','entry-00511','entry-00512'}
src = r'c:/Users/victor/Downloads/VulnGym/data/entries.jsonl'
out = r'c:/Users/victor/Downloads/VulnGym/tmp_entries_dump.txt'
blocks = []
for line in open(src, encoding='utf-8'):
    line = line.strip()
    if not line:
        continue
    row = json.loads(line)
    if row['entry_id'] in ids:
        blocks.append(json.dumps(row, ensure_ascii=False, indent=2))
open(out, 'w', encoding='utf-8').write(('\n' + '='*80 + '\n').join(blocks))
print('written', os.path.getsize(out), 'bytes to', out)
