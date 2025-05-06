# kodlama_arenasi/app.py

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, date, timedelta
import os
import json
import math
import subprocess # Eğer JS doğrulaması için Node.js kullanılıyorsa
import base64   # Eğer JS doğrulaması için Node.js kullanılıyorsa
import re       # Eğer Regex tabanlı JS doğrulaması kullanılıyorsa
from bs4 import BeautifulSoup # HTML doğrulaması için

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'varsayilan_cok_gizli_anahtar_12345')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Node.js Validator Ayarları (Eğer kullanılıyorsa) ---
NODE_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), 'js_validator', 'validator.js')
NODE_EXECUTABLE = 'node' 

# --- Lig ve Başarım Sabitleri ---
LEAGUES = {
    'Platin': 150, # Puan eşiklerini projenize göre ayarlayın
    'Altın': 75,
    'Gümüş': 30,
    'Bronz': 0,
}
LEAGUE_ORDER = ['Bronz', 'Gümüş', 'Altın', 'Platin']
PROMOTION_PERCENT = 20
DEMOTION_PERCENT = 10
MIN_LEAGUE_SIZE_FOR_ADJUSTMENT = 3

# --- Veritabanı Modelleri ---
completed_levels = db.Table('completed_levels',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('level_id', db.Integer, db.ForeignKey('level.id', ondelete='CASCADE'), primary_key=True)
)

user_achievements = db.Table('user_achievements',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('achievement_id', db.String(50), db.ForeignKey('achievement.id', ondelete='CASCADE'), primary_key=True),
    db.Column('unlocked_at', db.DateTime, nullable=False, default=datetime.utcnow)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    score = db.Column(db.Integer, default=0, index=True)
    initial_assessment_complete = db.Column(db.Boolean, default=True, nullable=False) # Deneme devre dışı, herkes tamamlamış sayılıyor
    current_difficulty = db.Column(db.Integer, default=1, nullable=False) # Varsayılan zorluk
    league = db.Column(db.String(50), default='Bronz', nullable=False)
    streak_count = db.Column(db.Integer, default=0, nullable=False)
    last_login_date = db.Column(db.DateTime, nullable=True)
    last_league_change_info = db.Column(db.String(150), nullable=True)
    has_seen_league_update = db.Column(db.Boolean, default=True, nullable=False)

    submissions = db.relationship('Submission', backref='author', lazy='dynamic', cascade="all, delete-orphan")
    completed = db.relationship('Level', secondary=completed_levels, lazy='dynamic',
                                backref=db.backref('completed_by_users', lazy='dynamic'))
    achievements = db.relationship('Achievement', secondary=user_achievements, lazy='dynamic',
                                   backref=db.backref('earned_by_users', lazy='dynamic'))

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def grant_achievement(self, achievement_id, session_flash_func=None):
        achievement = Achievement.query.get(achievement_id)
        if not achievement: return None
        if self.achievements.filter(Achievement.id == achievement_id).first(): return None
        self.achievements.append(achievement)
        if achievement.points_reward > 0: self.score += achievement.points_reward
        if session_flash_func:
            msg = f"🏆 Başarım Kazanıldı: {achievement.name}! ({achievement.description})"
            if achievement.points_reward > 0: msg += f" +{achievement.points_reward} Puan!"
            session_flash_func(msg, 'success achievement-flash')
        return achievement

    def __repr__(self):
        return f"User('{self.username}', Score: {self.score})"

class Level(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(20), nullable=False) # HTML, CSS, JS
    difficulty = db.Column(db.Integer, nullable=False, default=1)
    description = db.Column(db.Text, nullable=False)
    initial_code = db.Column(db.Text, nullable=True)
    expected_code = db.Column(db.Text, nullable=True)
    hints = db.Column(db.Text, nullable=True)
    points = db.Column(db.Integer, nullable=False, default=10)
    is_assessment = db.Column(db.Boolean, default=False, nullable=False) # Deneme seviyeleri False olacak
    validation_type = db.Column(db.String(50), default='exact_match', nullable=False)
    validation_criteria = db.Column(db.Text, nullable=True) # JSON string

    submissions = db.relationship('Submission', backref='level', lazy='dynamic', cascade="all, delete-orphan")

    def __repr__(self):
        return f"Level('{self.title}', Subject: {self.subject})"

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    level_id = db.Column(db.Integer, db.ForeignKey('level.id', ondelete='CASCADE'), nullable=False)
    submitted_code = db.Column(db.Text, nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Achievement(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    icon = db.Column(db.String(100), nullable=True)
    points_reward = db.Column(db.Integer, default=0)

# --- Yardımcı Fonksiyonlar (Doğrulama, Başarım Kontrolü vb.) ---
# Flask projesindeki validate_... ve check_..._achievements fonksiyonları buraya
# (veya ayrı bir utils.py dosyasına) taşınacak. Şimdilik placeholder.
def calculate_league(score):
    for league_name, min_score in sorted(LEAGUES.items(), key=lambda item: item[1], reverse=True):
        if score >= min_score: return league_name
    return 'Bronz'

def validate_exact_match(submitted_code, expected_code_str):
    submitted_clean = submitted_code.strip()
    expected_clean = (expected_code_str or "").strip()
    if submitted_clean == expected_clean:
        return True, "Kod beklenenle tam olarak eşleşiyor."
    return False, "Kod beklenenle tam olarak eşleşmiyor."

def validate_html_structure(submitted_code, criteria_json_str):
    try:
        criteria = json.loads(criteria_json_str or '{}') # criteria_json_str None ise boş dict
        soup = BeautifulSoup(submitted_code, 'lxml') # veya 'html.parser'

        if 'elements' not in criteria or not criteria['elements']:
            return False, "Doğrulama için element kriteri belirtilmemiş."

        for i, element_criteria in enumerate(criteria['elements']):
            tag_name = element_criteria.get('tag')
            required_text = element_criteria.get('text')
            required_parent_tag = element_criteria.get('parent')
            required_attributes = element_criteria.get('attributes', {})
            criterion_id_for_msg = f"Kriter {i+1} ('{tag_name}')"

            if not tag_name:
                print(f"DEBUG: {criterion_id_for_msg} - 'tag' belirtilmemiş, atlanıyor.")
                continue # Geçerli bir tag adı yoksa bu kriteri atla

            # Belirtilen tag'e sahip tüm elementleri bul
            found_elements = soup.find_all(tag_name)

            if not found_elements:
                return False, f"{criterion_id_for_msg}: Sayfada hiç `<{tag_name}>` etiketi bulunamadı."

            element_matched_criteria = False
            specific_error_message = f"{criterion_id_for_msg}: Bu etiket için belirtilen tüm koşullar sağlanmadı."

            for element in found_elements:
                # 1. Metin İçeriği Kontrolü
                text_match = True # Varsayılan olarak doğru, metin istenmiyorsa
                if required_text is not None: # Sadece metin kriteri varsa kontrol et
                    actual_text = element.get_text(strip=True)
                    text_match = (actual_text == required_text)
                    if not text_match:
                        specific_error_message = f"{criterion_id_for_msg}: `<{tag_name}>` etiketi bulundu, ancak metin içeriği ('{actual_text}') beklenen ('{required_text}') ile eşleşmiyor."
                        continue # Bu element uymadı, aynı tag'e sahip diğer elemente bak

                # 2. Ebeveyn Etiket Kontrolü
                parent_match = True # Varsayılan olarak doğru, ebeveyn istenmiyorsa
                if required_parent_tag:
                    parent_match = (element.parent is not None and element.parent.name == required_parent_tag)
                    if not parent_match:
                        actual_parent_name = element.parent.name if element.parent else "yok"
                        specific_error_message = f"{criterion_id_for_msg}: `<{tag_name}>` etiketi bulundu, ancak beklenen ebeveyni (`<{required_parent_tag}>`) içinde değil (mevcut ebeveyn: `<{actual_parent_name}>`)."
                        continue # Bu element uymadı

                # 3. Özellik (Attribute) Kontrolü
                attributes_match = True # Varsayılan olarak doğru
                for attr_name, expected_value in required_attributes.items():
                    actual_value = element.get(attr_name)
                    if expected_value is True: # Sadece özelliğin varlığı kontrol ediliyor
                        if actual_value is None:
                            attributes_match = False
                            specific_error_message = f"{criterion_id_for_msg}: `<{tag_name}>` etiketinde beklenen `{attr_name}` özelliği bulunamadı."
                            break # Bu elementin özellikleri uymadı
                    elif str(actual_value) != str(expected_value): # Değerlerin tam eşleşmesi (stringe çevirerek)
                        attributes_match = False
                        specific_error_message = f"{criterion_id_for_msg}: `<{tag_name}>` etiketindeki `{attr_name}` özelliğinin değeri ('{actual_value}') beklenen ('{expected_value}') ile eşleşmiyor."
                        break # Bu elementin özellikleri uymadı
                
                if not attributes_match:
                    continue # Bu element uymadı

                # Eğer tüm alt kriterler bu element için eşleştiyse
                if text_match and parent_match and attributes_match:
                    element_matched_criteria = True
                    break # Bu element kriteri sağladı, diğer elementlere bakmaya gerek yok

            if not element_matched_criteria:
                return False, specific_error_message # En son karşılaşılan spesifik hatayı döndür

        # Eğer 'elements' listesindeki tüm kriterler başarıyla geçildiyse
        return True, "HTML yapısı tüm kriterlere uyuyor."

    except json.JSONDecodeError:
        return False, "Seviye yapılandırma hatası: validation_criteria geçerli bir JSON değil."
    except Exception as e:
        print(f"validate_html_structure içinde beklenmedik hata: {e}") # Hata ayıklama için
        return False, f"HTML kodunuz işlenirken bir hata oluştu: {str(e)}"

def validate_css_rule(submitted_code, criteria_json_str):
    try:
        criteria = json.loads(criteria_json_str or '{}') # criteria_json_str None ise boş dict
        
        if 'rules' not in criteria or not criteria['rules']:
            return False, "Doğrulama için CSS kural kriteri belirtilmemiş."

        submitted_code_clean = submitted_code # Belki yorumları vs. temizlemek gerekebilir

        for i, rule_criteria in enumerate(criteria['rules']):
            selector = rule_criteria.get('selector')
            prop = rule_criteria.get('property')
            value = rule_criteria.get('value')
            criterion_id_for_msg = f"Kriter {i+1} ('{selector}' için '{prop}')"

            if not selector or not prop or not value:
                print(f"DEBUG: {criterion_id_for_msg} - Eksik kural bilgisi, atlanıyor.")
                continue # Eksik kural kriteri varsa bu kuralı atla

            pattern_str = rf'{re.escape(selector)}\s*{{[^}}]*{re.escape(prop)}\s*:\s*{re.escape(value)}\s*;\s*[^}}]*}}'

            selector_blocks = re.findall(rf'{re.escape(selector)}\s*{{([^}}]*)}}', submitted_code_clean, re.IGNORECASE | re.DOTALL)
            if not selector_blocks:
                 return False, f"{criterion_id_for_msg}: `{selector}` için bir CSS kural bloğu ({{...}}) bulunamadı."

            found_rule_in_block = False
            for block_content in selector_blocks:
                # Blok içinde property: value; ara
                prop_value_pattern = rf'{re.escape(prop)}\s*:\s*{re.escape(value)}\s*;'
                if re.search(prop_value_pattern, block_content, re.IGNORECASE):
                    found_rule_in_block = True
                    break # Kural bu blokta bulundu
            
            if not found_rule_in_block:
                return False, f"{criterion_id_for_msg}: `{selector}` seçicisi içinde `{prop}: {value};` kuralı bulunamadı veya yanlış yazılmış."

        # Eğer 'rules' listesindeki tüm kriterler başarıyla geçildiyse
        return True, "CSS kuralları tüm kriterlere uyuyor."

    except json.JSONDecodeError:
        return False, "Seviye yapılandırma hatası: validation_criteria geçerli bir JSON değil."
    except re.error as e:
        print(f"CSS Regex Hatası: {e}")
        return False, "Seviye yapılandırma hatası: Geçersiz Regex deseni."
    except Exception as e:
        print(f"validate_css_rule içinde beklenmedik hata: {e}")
        return False, f"CSS kodunuz işlenirken bir hata oluştu: {str(e)}"
    
def validate_js_pattern(submitted_code, criteria_json_str):
    try:
        criteria = json.loads(criteria_json_str or '{}')
        if 'patterns' in criteria:
            for p_data in criteria['patterns']:
                pattern_to_search = p_data.get('pattern')
                error_msg_on_fail = p_data.get('error', 'Belirtilen JavaScript deseni bulunamadı veya eşleşmedi.')
                flags = 0
                if p_data.get('ignorecase'): flags |= re.IGNORECASE
                if p_data.get('multiline'): flags |= re.MULTILINE
                if p_data.get('dotall'): flags |= re.DOTALL

                if not pattern_to_search: # Eğer desen boşsa bu kriteri atla veya hata ver
                    print(f"UYARI: JS Desen kriterinde boş desen bulundu: {p_data}")
                    continue 

                if not re.search(pattern_to_search, submitted_code, flags):
                    return False, error_msg_on_fail
        # Tüm desenler (eğer varsa) başarıyla bulunduysa
        return True, "JavaScript deseni tüm kriterlere uyuyor."
    except json.JSONDecodeError:
        return False, "Seviye yapılandırma hatası: JS Desen kriterleri geçerli bir JSON değil."
    except re.error as e:
        print(f"JS Desen Regex Hatası: {e}")
        return False, "Seviye yapılandırma hatası: Geçersiz Regex deseni."
    except Exception as e:
        print(f"validate_js_pattern içinde beklenmedik hata: {e}")
        return False, f"JavaScript deseniniz doğrulanırken bir hata oluştu: {str(e)}"

def validate_js_execution(submitted_code, criteria_json_str):
    if not os.path.exists(NODE_SCRIPT_PATH):
        print("HATA: js_validator/validator.js bulunamadı!")
        return False, "JavaScript doğrulama altyapısı (validator.js) sunucuda bulunamadı."
    
    if not NODE_EXECUTABLE: # Eğer node yolu boşsa
        print("HATA: NODE_EXECUTABLE ayarlanmamış!")
        return False, "Node.js çalıştırılabilir yolu ayarlanmamış."

    try:
        # Kodu ve kriterleri base64 ile kodla (komut satırı argümanlarında özel karakter sorunlarını önler)
        code_b64 = base64.b64encode(submitted_code.encode('utf-8')).decode('utf-8')
        # criteria_json_str None ise boş JSON objesi gönder
        criteria_to_encode = criteria_json_str if criteria_json_str else '{}'
        criteria_b64 = base64.b64encode(criteria_to_encode.encode('utf-8')).decode('utf-8')

        # Node.js işlemini başlat
        timeout_seconds = 5 # Kodun çalışması için maksimum süre
        
        print(f"DEBUG: Node.js çağrılıyor: {NODE_EXECUTABLE} {NODE_SCRIPT_PATH} <kod> <kriter>")

        process = subprocess.run(
            [NODE_EXECUTABLE, NODE_SCRIPT_PATH, code_b64, criteria_b64],
            capture_output=True, # stdout ve stderr'i yakala
            text=True,           # Çıktıyı metin olarak al
            timeout=timeout_seconds,
            check=False          # Hata durumunda Python exception fırlatmasın, stderr'i ve returncode'u kontrol edelim
        )

        # Node.js scriptinden gelen çıktıyı (stdout) işle
        if process.returncode == 0 and process.stdout:
            try:
                result = json.loads(process.stdout)
                is_correct = result.get('success', False)
                message = result.get('message', 'Bilinmeyen doğrulama sonucu.')
                
                # Node.js scriptinden gelen bir hata varsa, onu da mesaja ekleyebiliriz
                if not is_correct and result.get('error'):
                    message += f" (Detay: {result.get('error')})"
                
                print(f"DEBUG: Node.js sonucu: Success={is_correct}, Message='{message}'")
                return is_correct, message
            except json.JSONDecodeError:
                print(f"HATA: Node.js'den gelen JSON parse edilemedi: {process.stdout}")
                return False, "Doğrulayıcıdan geçersiz bir yanıt alındı (JSON parse hatası)."
        else:
            # Node.js işlemi hata koduyla bitti veya stdout boş veya stderr'de çıktı var
            error_output = process.stderr or process.stdout or "Bilinmeyen Node.js hatası"
            print(f"HATA: Node.js Çalıştırma Hatası (Return Code: {process.returncode}): {error_output}")
            # Kullanıcıya gösterilecek mesajı daha anlaşılır yapalım
            user_message = f"Kodunuz çalıştırılırken sunucu tarafında bir sorun oluştu."
            if "SyntaxError" in error_output:
                user_message = f"Kodunuzda bir syntax hatası var gibi görünüyor. Lütfen kontrol edin. (Detay: {error_output.splitlines()[0] if error_output else ''})"
            elif "ReferenceError" in error_output:
                 user_message = f"Tanımlanmamış bir değişken veya fonksiyon kullanmaya çalışıyor olabilirsiniz. (Detay: {error_output.splitlines()[0] if error_output else ''})"
            # Diğer yaygın hatalar için de benzer kontroller eklenebilir.
            return False, user_message

    except subprocess.TimeoutExpired:
        print(f"HATA: Node.js zaman aşımına uğradı ({timeout_seconds}s). Kod muhtemelen sonsuz döngüye girdi.")
        return False, f"Kodunuz izin verilen süreden ({timeout_seconds} saniye) daha uzun çalıştı. Sonsuz döngü olabilir mi?"
    except FileNotFoundError:
         print(f"HATA: Node.js çalıştırılamadı. '{NODE_EXECUTABLE}' komutu sistemde bulunamıyor veya PATH'de değil.")
         return False, "JavaScript doğrulayıcı çalıştırılamadı (Sunucu yapılandırma sorunu)."
    except Exception as e:
        print(f"HATA: validate_js_execution içinde beklenmedik Python hatası: {e}")
        import traceback
        traceback.print_exc()
        return False, f"JavaScript kodunuz doğrulanırken beklenmedik bir sunucu hatası oluştu."

def validate_multi_task_normal(submitted_code, criteria_json_str):
    # BU FONKSİYONUN İÇİNİ FLASK PROJESİNDEKİ DENEME SEVİYESİ GÖREV KONTROL MANTIĞIYLA DOLDUR
    print(f"DEBUG: validate_multi_task_normal çağrıldı. Kriter: {criteria_json_str}")
    # ... (Her bir task'ı validate_html_structure, validate_css_rule vb. ile kontrol et) ...
    return False, "Çoklu Görev Doğrulaması Henüz Tamamlanmadı (placeholder)."

def check_level_completion_achievements(user, completed_level, flash_func):
    # ... (Flask projesindeki başarım mantığı buraya) ...
    # Örnek: user.grant_achievement('ilk_adim', flash_func)
    print(f"DEBUG: check_level_completion_achievements çağrıldı - User: {user.username}, Level: {completed_level.title}")
    pass

def check_streak_achievements(user, flash_func):
    # ... (Flask projesindeki başarım mantığı buraya) ...
    print(f"DEBUG: check_streak_achievements çağrıldı - User: {user.username}, Streak: {user.streak_count}")
    pass

def check_league_achievements(user, old_league, new_league, flash_func):
    # ... (Flask projesindeki başarım mantığı buraya) ...
    print(f"DEBUG: check_league_achievements çağrıldı - User: {user.username}, New League: {new_league}")
    pass

# --- Rotalar ---
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        error = False
        # ... (Form doğrulama, kullanıcı adı/e-posta kontrolü) ...
        if not username or not email or not password or not confirm_password: flash('Lütfen tüm alanları doldurun.', 'danger'); error = True
        if password != confirm_password: flash('Şifreler eşleşmiyor!', 'danger'); error = True
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first(): flash('Kullanıcı adı veya e-posta zaten mevcut.', 'danger'); error = True
        if error: return render_template('register.html')

        new_user = User(username=username, email=email, initial_assessment_complete=True, current_difficulty=1)
        new_user.set_password(password)
        try:
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session['league'] = new_user.league
            flash('Hesabınız başarıyla oluşturuldu ve giriş yaptınız!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback(); flash(f'Kayıt sırasında bir hata oluştu: {e}', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user_input = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter((User.username == user_input) | (User.email == user_input)).first()
        if user and user.check_password(password):
            today, now = date.today(), datetime.utcnow()
            streak_updated = False
            if user.last_login_date is None: user.streak_count = 1; streak_updated = True
            else:
                delta = today - user.last_login_date.date()
                if delta.days == 1: user.streak_count += 1; streak_updated = True
                elif delta.days > 1: user.streak_count = 1; streak_updated = True
            if streak_updated: check_streak_achievements(user)
            user.last_login_date = now
            db.session.add(user); db.session.commit() # Hata kontrolü eklenebilir
            session['user_id'] = user.id
            session['username'] = user.username
            session['league'] = user.league
            msg = 'Başarıyla giriş yaptınız!'
            if streak_updated and user.streak_count > 1: msg += f" 🔥 {user.streak_count} günlük seri!"
            flash(msg, 'success')
            return redirect(url_for('dashboard')) # Deneme kontrolü kaldırıldı
        else: flash('Giriş başarısız.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); flash('Başarıyla çıkış yaptınız.', 'info'); return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: flash('Giriş yapmalısınız.', 'danger'); return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user: session.clear(); flash('Kullanıcı bulunamadı.', 'danger'); return redirect(url_for('login'))
    if not user.has_seen_league_update and user.last_league_change_info:
        flash(user.last_league_change_info, 'info')
        user.has_seen_league_update = True; user.last_league_change_info = None
        db.session.add(user); db.session.commit() # Hata kontrolü

    completed_ids = {lvl.id for lvl in user.completed.all()}
    next_level = Level.query.filter(Level.is_assessment == False, Level.difficulty == user.current_difficulty).filter(Level.id.notin_(completed_ids)).order_by(Level.id).first()
    if not next_level: next_level = Level.query.filter(Level.is_assessment == False, Level.difficulty > user.current_difficulty).filter(Level.id.notin_(completed_ids)).order_by(Level.difficulty, Level.id).first()
    if not next_level: next_level = Level.query.filter(Level.is_assessment == False).filter(Level.id.notin_(completed_ids)).order_by(Level.difficulty, Level.id).first()
    return render_template('dashboard.html', user=user, next_level_id=next_level.id if next_level else None)

# /assessment rotası devre dışı bırakıldı.
# @app.route('/assessment')
# def assessment():
#     return "Deneme seviyesi geçici olarak devre dışı.", 403

@app.route('/level/<int:level_id>')
def view_level(level_id):
    if 'user_id' not in session: flash('Giriş yapmalısınız.', 'danger'); return redirect(url_for('login'))
    level = Level.query.get_or_404(level_id)
    if level.is_assessment: abort(404) # Deneme seviyesine direkt erişim yok
    user = User.query.get(session['user_id'])
    is_completed = level in user.completed.all()
    return render_template('level.html', level=level, is_completed=is_completed)

@app.route('/submit_answer/<int:level_id>', methods=['POST'])
def submit_answer(level_id):
    if 'user_id' not in session: return jsonify(success=False, message="Giriş yapmalısınız."), 401
    data = request.get_json();
    if not data or 'code' not in data: return jsonify(success=False, message="Kod gönderilmedi."), 400
    
    submitted_code = data['code']
    user = User.query.get(session['user_id'])
    level = Level.query.get(level_id)

    if not level or not user : return jsonify(success=False, message="Seviye veya kullanıcı bulunamadı."), 404
    
    if user.completed.filter(Level.id == level_id).first():
        return jsonify(success=False, message="Bu seviyeyi zaten tamamladınız.", already_completed=True)

    is_correct = False
    validation_message = f"Bilinmeyen veya desteklenmeyen doğrulama tipi: '{level.validation_type}'" # Daha iyi varsayılan

    print(f"DEBUG (submit_answer): Seviye ID: {level.id}, Validation Type: '{level.validation_type}'")

    if level.validation_type == 'exact_match':
        is_correct, validation_message = validate_exact_match(submitted_code, level.expected_code)
    elif level.validation_type == 'html_structure':
        is_correct, validation_message = validate_html_structure(submitted_code, level.validation_criteria)
    elif level.validation_type == 'css_rule':
        is_correct, validation_message = validate_css_rule(submitted_code, level.validation_criteria)
    elif level.validation_type == 'js_pattern':
        is_correct, validation_message = validate_js_pattern(submitted_code, level.validation_criteria)
    elif level.validation_type == 'js_execute':
        is_correct, validation_message = validate_js_execution(submitted_code, level.validation_criteria)
    elif level.validation_type == 'multi_task_normal':
        is_correct, validation_message = validate_multi_task_normal(submitted_code, level.validation_criteria)
    
    print(f"DEBUG (submit_answer): Doğrulama Sonucu: is_correct={is_correct}, message='{validation_message}'")
    
    new_submission = Submission(user_id=user.id, level_id=level.id, submitted_code=submitted_code, is_correct=is_correct)
    db.session.add(new_submission)
    
    response_data = {
        "success": is_correct,
        "message": validation_message,
        "points_earned": 0, "next_level_id": None,
        "current_score": user.score, "current_league": user.league,
        "league_change": None
    }

    if is_correct:
        response_data["message"] = "Tebrikler! Doğru cevap! " + validation_message
        response_data["points_earned"] = level.points
        user.score += level.points
        user.completed.append(level)
        check_level_completion_achievements(user, level, flash)
        old_league = user.league; new_league = calculate_league(user.score)
        if new_league != old_league:
            response_data["league_change"] = f"Tebrikler! {new_league} ligine yükseldin!"
            user.league = new_league; session['league'] = new_league
            check_league_achievements(user, old_league, new_league, flash)
        db.session.add(user)
        
        completed_ids = {lvl.id for lvl in user.completed.all()}
        next_lvl_obj = Level.query.filter(Level.is_assessment == False, Level.difficulty == user.current_difficulty, Level.id.notin_(completed_ids)).order_by(Level.id).first()
        if not next_lvl_obj: next_lvl_obj = Level.query.filter(Level.is_assessment == False, Level.difficulty > user.current_difficulty, Level.id.notin_(completed_ids)).order_by(Level.difficulty, Level.id).first()
        if not next_lvl_obj: next_lvl_obj = Level.query.filter(Level.is_assessment == False, Level.id.notin_(completed_ids)).order_by(Level.difficulty, Level.id).first()
        if next_lvl_obj: response_data["next_level_id"] = next_lvl_obj.id
        
        response_data["current_score"] = user.score
        response_data["current_league"] = user.league
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"DB Hatası submit_answer commit sırasında: {e}")
        return jsonify(success=False, message="Cevap kaydedilirken sunucu hatası oluştu."), 500
    
    return jsonify(response_data)

@app.route('/leaderboard')
def leaderboard():
    users = User.query.order_by(User.score.desc()).all()
    return render_template('leaderboard.html', users=users)

@app.route('/my_achievements')
def my_achievements():
    if 'user_id' not in session: flash('Giriş yapmalısınız.', 'danger'); return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    all_achievements = Achievement.query.order_by(Achievement.name).all()
    earned_ids = {ach.id for ach in user.achievements.all()}
    return render_template('my_achievements.html', all_achievements=all_achievements, earned_ids=earned_ids, user=user)

@app.route('/get_user_info') # Navbar için AJAX
def get_user_info():
    if 'user_id' not in session: return jsonify(success=False, error="Not logged in"), 401
    user = User.query.get(session['user_id'])
    if not user: return jsonify(success=False, error="User not found"), 404
    return jsonify(success=True, username=user.username, score=user.score, league=user.league)

# --- CLI Komutları ---
@app.cli.command("run-league-update") # flask run-league-update
def run_league_update_command():
    # ... (run_league_adjustments fonksiyonunun çağrılması) ...
    print("Lig güncelleme komutu çalıştırıldı (fonksiyonu eklemelisiniz).")

@app.cli.command("init-achievements") # flask init-achievements
def init_achievements_command():
    # ... (Başarım ekleme mantığı) ...
    print("Başarım başlatma komutu çalıştırıldı (fonksiyonu eklemelisiniz).")

def add_initial_levels_and_assessment():
    if not Level.query.first():
        print("Başlangıç seviyeleri ekleniyor (deneme seviyesi devre dışı)...")
        levels_data = [
            # Flask projesindeki tüm seviyeler buraya eklenecek
            # ve 'is_assessment': False olduğundan emin olunacak.
            # Örnek bir tane:
            {'title': 'HTML Temelleri: İlk Başlık', 'subject': 'HTML', 'difficulty': 1,
             'description': '...', 'initial_code': '...', 'expected_code': '<h1>Merhaba Dünya</h1>',
             'hints': '...', 'points': 5, 'is_assessment': False, 'validation_type': 'exact_match'},
             # DİĞER TÜM SEVİYELER BURAYA EKLENECEK
        ]
        for data in levels_data:
            db.session.add(Level(**data))
        try: db.session.commit(); print("Seviyeler eklendi.")
        except: db.session.rollback(); print("Seviye ekleme hatası.")
    else: print("Veritabanında seviyeler zaten mevcut.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        add_initial_levels_and_assessment() # Başlangıç seviyelerini yükle
        # init_achievements_command() # Başarımları CLI ile yüklemek daha iyi
    app.run(debug=True)