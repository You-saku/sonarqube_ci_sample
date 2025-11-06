#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SonarQube for IDE テスト用の安全でないコード
様々なセキュリティ脆弱性を含むサンプル
"""

import os
import subprocess
import pickle
import hashlib
import random
import sqlite3
import requests
from urllib.parse import urlparse

# セキュリティ脆弱性1: ハードコードされた認証情報
SECRET_KEY = "hardcoded_secret_123"
DATABASE_PASSWORD = "admin123"
API_TOKEN = "sk-1234567890abcdef"

# セキュリティ脆弱性2: SQLインジェクション
def unsafe_database_query(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 危険: ユーザー入力を直接SQLクエリに結合
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

# セキュリティ脆弱性3: コマンドインジェクション
def unsafe_command_execution(filename):
    # 危険: ユーザー入力を直接シェルコマンドに使用
    command = f"cat {filename}"
    result = os.system(command)
    return result

def unsafe_subprocess_call(user_input):
    # 危険: shell=Trueでユーザー入力を使用
    subprocess.call(f"echo {user_input}", shell=True)

# セキュリティ脆弱性4: パストラバーサル
def unsafe_file_access(file_path):
    # 危険: ファイルパスの検証なし
    with open(file_path, 'r') as f:
        return f.read()

# セキュリティ脆弱性5: 安全でないデシリアライゼーション
def unsafe_pickle_load(data):
    # 危険: 信頼できないソースからのpickleデータをロード
    return pickle.loads(data)

# セキュリティ脆弱性6: 弱い暗号化
def weak_hash_function(password):
    # 危険: 弱いハッシュアルゴリズムを使用
    return hashlib.md5(password.encode()).hexdigest()

# セキュリティ脆弱性7: 安全でない乱数生成
def generate_weak_token():
    # 危険: 暗号学的に安全でない乱数生成器を使用
    return str(random.randint(1000000, 9999999))

# セキュリティ脆弱性8: SSL証明書検証の無効化
def unsafe_http_request(url):
    # 危険: SSL証明書の検証を無効化
    response = requests.get(url, verify=False)
    return response.text

# セキュリティ脆弱性9: 機密情報のログ出力
def log_sensitive_data(username, password):
    # 危険: 機密情報をログに出力
    print(f"User login: {username}, Password: {password}")

# セキュリティ脆弱性10: 無制限のファイルアップロード
def unsafe_file_upload(file_content, filename):
    # 危険: ファイルサイズやタイプの制限なし
    with open(f"/uploads/{filename}", 'wb') as f:
        f.write(file_content)

# セキュリティ脆弱性11: XMLエンティティ攻撃に脆弱
def unsafe_xml_parsing(xml_content):
    import xml.etree.ElementTree as ET
    # 危険: 外部エンティティの処理を無効化していない
    root = ET.fromstring(xml_content)
    return root

# セキュリティ脆弱性12: 弱いパスワード要件
def weak_password_validation(password):
    # 危険: 非常に弱いパスワード要件
    if len(password) >= 3:
        return True
    return False

# セキュリティ脆弱性13: 不適切な例外処理
def unsafe_exception_handling():
    try:
        # 何らかの処理
        result = 1 / 0
    except:
        # 危険: すべての例外を隠蔽
        pass

# セキュリティ脆弱性14: タイミング攻撃に脆弱な比較
def unsafe_string_comparison(user_token, valid_token):
    # 危険: タイミング攻撃に脆弱な文字列比較
    return user_token == valid_token

# セキュリティ脆弱性15: 開発用設定の本番環境での使用
DEBUG = True
ALLOWED_HOSTS = ['*']

def main():
    """
    メイン関数 - 様々な脆弱性のあるコードを実行
    """
    print("SonarQube for IDE セキュリティテスト開始")
    
    # 脆弱性のあるコードの実行例
    user_id = "1; DROP TABLE users; --"  # SQLインジェクション攻撃
    results = unsafe_database_query(user_id)
    
    filename = "../../../etc/passwd"  # パストラバーサル攻撃
    file_content = unsafe_file_access(filename)
    
    password = "123"  # 弱いパスワード
    hashed = weak_hash_function(password)
    
    token = generate_weak_token()
    print(f"生成されたトークン: {token}")
    
    log_sensitive_data("admin", "secret123")
    
    print("テスト完了")

if __name__ == "__main__":
    main()
