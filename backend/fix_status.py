import sqlite3
c = sqlite3.connect('auditshield.db')
c.execute("UPDATE audits SET status=? WHERE id=?", ('verified', 'edd6b7ee-1611-49e4-a4b9-a402b7f12bfc'))
c.commit()
print('Status reset to verified.')
