import db
import data_vault

def run_update():
    conn = db.get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE packages 
        SET name = 'Sabro Broadband All-Access Pass', price_pkr = 0, duration_days = 30, 
            max_connections = 2, allowed_categories = 'all', is_active = 1 
        WHERE code = 'basic'
    """)
    cursor.execute("""
        UPDATE packages 
        SET name = 'Sabro Vision Commercial Pass', price_pkr = 150, duration_days = 30, 
            max_connections = 1, allowed_categories = 'all', is_active = 1 
        WHERE code = 'all_in_one'
    """)
    cursor.execute("UPDATE packages SET is_active = 0 WHERE code NOT IN ('basic', 'all_in_one')")
    cursor.execute("UPDATE settings SET value = '150' WHERE key IN ('monthly_price', 'outside_customer_default_price')")
    cursor.execute("UPDATE settings SET value = '2' WHERE key = 'sabro_isp_free_screens'")
    conn.commit()

    rows = cursor.execute("SELECT id, name, code, price_pkr, max_connections, allowed_categories, is_active FROM packages WHERE is_active = 1").fetchall()
    print("ACTIVE PACKAGES:")
    for r in rows:
        print(dict(r))

    conn.close()
    data_vault.export_vault_snapshot()
    print("Vault snapshot exported successfully.")

if __name__ == '__main__':
    run_update()
