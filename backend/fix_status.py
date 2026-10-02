import sqlite3
c = sqlite3.connect('auditshield.db')
c.execute("UPDATE audits SET status=? WHERE domain=?", ('verified', 'scanme.nmap.org'))
c.commit()
print('Status updated.')
