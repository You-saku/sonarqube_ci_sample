#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SonarQube for IDE テスト用の安全でないコード
様々なセキュリティ脆弱性を含むサンプル
"""

import os
import subprocess
import json
import hashlib
import secrets
import sqlite3
import requests
from urllib.parse import urlparse

# 安全な設定: 環境変数から認証情報を取得
SECRET_KEY = os.environ.get("SECRET_KEY", "default_secret_key")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "default_password")
API_TOKEN = os.environ.get("API_TOKEN", "default_token")

# 安全なデータベースクエリ: パラメータ化クエリを使用
def safe_database_query(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 安全: パラメータ化クエリを使用してSQLインジェクションを防ぐ
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    result = cursor.fetchall()
    conn.close()
    return result

# 安全なコマンド実行: 入力検証とsubprocess.runを使用
def safe_command_execution(filename):
    # 入力検証: ファイル名に危険な文字が含まれていないかチェック
    if not filename or '..' in filename or '/' in filename:
        raise ValueError("無効なファイル名です")
    
    # 安全: subprocess.runを使用し、シェルを無効にする
    try:
        result = subprocess.run(['cat', filename], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"エラー: {e}"

def safe_subprocess_call(user_input):
    # 入力検証: 危険な文字をチェック
    if not user_input or any(char in user_input for char in [';', '|', '&', '$', '`']):
        raise ValueError("無効な入力です")
    
    # 安全: subprocess.runを使用し、shell=Falseを指定
    try:
        subprocess.run(['echo', user_input], check=True)
    except subprocess.CalledProcessError as e:
        print(f"エラー: {e}")

# 安全なファイルアクセス: パストラバーサル攻撃を防ぐ
def safe_file_access(file_path):
    # 安全なベースディレクトリを定義
    base_directory = "/var/app/data"
    
    # パスを正規化し、ベースディレクトリ内に制限
    try:
        normalized_path = os.path.normpath(os.path.join(base_directory, file_path))
        # ベースディレクトリ外へのアクセスを防ぐ
        if not normalized_path.startswith(base_directory):
            raise ValueError("不正なファイルパスです")
        
        with open(normalized_path, 'r') as f:
            return f.read()
    except (OSError, IOError) as e:
        return f"ファイルアクセスエラー: {e}"

# 安全なデータシリアライゼーション: JSONを使用
def safe_json_load(data):
    # 安全: JSONを使用して信頼できないソースからのデータを処理
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        return f"JSON解析エラー: {e}"

# 安全なハッシュ関数: 強力なアルゴリズムを使用
def secure_hash_function(password):
    # 安全: SHA256などの強力なハッシュアルゴリズムを使用
    salt = secrets.token_hex(16)  # ランダムソルトを生成
    return hashlib.sha256((password + salt).encode()).hexdigest(), salt

# 安全な乱数生成: 暗号学的に安全な乱数生成器を使用
def generate_secure_token():
    # 安全: secretsモジュールを使用して暗号学的に安全なトークンを生成
    return secrets.token_urlsafe(32)

# 安全なHTTPリクエスト: SSL証明書検証を有効化
def safe_http_request(url):
    # 安全: SSL証明書の検証を有効にする
    try:
        response = requests.get(url, verify=True, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        return f"HTTPリクエストエラー: {e}"

# 安全なログ出力: 機密情報を隠す
def safe_log_user_action(username, success=True):
    # 安全: パスワードなどの機密情報をログに出力しない
    status = "成功" if success else "失敗"
    print(f"ユーザーログイン試行: {username}, ステータス: {status}")

# 安全なファイルアップロード: ファイルサイズとタイプの制限
def safe_file_upload(file_content, filename):
    # ファイルサイズ制限 (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024
    if len(file_content) > MAX_FILE_SIZE:
        raise ValueError("ファイルサイズが制限を超えています")
    
    # 許可されるファイル拡張子
    allowed_extensions = ['.txt', '.jpg', '.png', '.pdf', '.doc']
    file_extension = os.path.splitext(filename)[1].lower()
    if file_extension not in allowed_extensions:
        raise ValueError("許可されていないファイルタイプです")
    
    # 安全なファイルパス
    safe_filename = os.path.basename(filename)  # ディレクトリトラバーサルを防ぐ
    upload_path = os.path.join("/var/uploads", safe_filename)
    
    try:
        with open(upload_path, 'wb') as f:
            f.write(file_content)
    except IOError as e:
        raise IOError(f"ファイルアップロードエラー: {e}")

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
