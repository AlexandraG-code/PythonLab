import pandas as pd
import numpy as np
import warnings

warnings.filterwarnings('ignore')

# 1. Загрузка данных
print("📥 Загрузка данных...")
df = pd.read_parquet('dns.parquet')
print(f"✅ Данные загружены: {df.shape[0]} строк, {df.shape[1]} столбцов")
print(f"✅ Метка класса: 'GlobalClass' (скорее всего: normal/malicious)")

# 2. Посмотрим распределение классов
if 'GlobalClass' in df.columns:
    print("\n🎯 РАСПРЕДЕЛЕНИЕ КЛАССОВ:")
    class_dist = df['GlobalClass'].value_counts()
    for class_name, count in class_dist.items():
        percentage = (count / len(df)) * 100
        print(f"   {class_name}: {count:,} записей ({percentage:.1f}%)")

# 3. Анализ подозрительных признаков
print("\n" + "=" * 60)
print("🔎 ПОИСК ПОДОЗРИТЕЛЬНЫХ ПАТТЕРНОВ")
print("=" * 60)

# Создадим копию для анализа
analysis_df = df.copy()

# 3.1. Аномалии в частотах запросов
print("\n📊 АНОМАЛИИ В ЧАСТОТАХ ЗАПРОСОВ:")

# Подозрительные частоты (слишком высокие/низкие)
suspicious_freq_features = {
    'NULL_frequency': 'NULL-запросы (редкие, могут быть подозрительными)',
    'TXT_frequency': 'TXT-запросы (используются для данных, возможна эксфильтрация)',
    'OPT_frequency': 'OPT-запросы (EDNS, могут использоваться для атак)'
}

for feature, description in suspicious_freq_features.items():
    if feature in analysis_df.columns:
        high_threshold = analysis_df[feature].quantile(0.95)  # верхние 5%
        suspicious = analysis_df[analysis_df[feature] > high_threshold]
        if len(suspicious) > 0:
            print(f"   • {description}: {len(suspicious):,} записей с высокой частотой")
            if 'GlobalClass' in analysis_df.columns:
                if 'malicious' in analysis_df['GlobalClass'].values:
                    malicious_in_susp = suspicious[suspicious['GlobalClass'] == 'malicious']
                    print(f"     Среди них malicious: {len(malicious_in_susp):,}")

# 3.2. Аномалии в энтропии
print("\n🔐 АНОМАЛИИ В ЭНТРОПИИ:")
entropy_cols = ['entropy', 'rr_name_entropy']
for col in entropy_cols:
    if col in analysis_df.columns:
        high_entropy = analysis_df[col].quantile(0.95)
        low_entropy = analysis_df[col].quantile(0.05)

        high_susp = analysis_df[analysis_df[col] > high_entropy]
        low_susp = analysis_df[analysis_df[col] < low_entropy]

        print(f"   • {col}:")
        print(f"     - Высокая энтропия (> {high_entropy:.2f}): {len(high_susp):,} записей")
        print(f"     - Низкая энтропия (< {low_entropy:.2f}): {len(low_susp):,} записей")

# 3.3. Аномалии в длине имен
print("\n📏 АНОМАЛИИ В ДЛИНЕ ИМЕН:")
if 'len' in analysis_df.columns or 'rr_name_length' in analysis_df.columns:
    len_col = 'len' if 'len' in analysis_df.columns else 'rr_name_length'

    # Слишком длинные имена (> 95 перцентиль)
    long_threshold = analysis_df[len_col].quantile(0.95)
    very_long = analysis_df[analysis_df[len_col] > 63]  # RFC ограничение
    long_names = analysis_df[analysis_df[len_col] > long_threshold]

    print(f"   • Очень длинные имена (> 63 символов): {len(very_long):,} записей")
    print(f"   • Длинные имена (> {long_threshold:.0f} символов): {len(long_names):,} записей")

# 3.4. Подозрительные TTL значения
print("\n⏱️  АНОМАЛИИ В TTL:")
ttl_cols = ['unique_ttl', 'ttl_mean', 'ttl_variance']
for col in ttl_cols:
    if col in analysis_df.columns:
        # Низкий TTL может быть признаком быстрого флудинга
        if col == 'unique_ttl':
            low_ttl = analysis_df[analysis_df[col] < 10]  # Меньше 10 секунд
            print(f"   • {col} < 10 сек: {len(low_ttl):,} записей")
        # Высокая вариация TTL
        if col == 'ttl_variance':
            high_var = analysis_df[analysis_df[col] > analysis_df[col].quantile(0.95)]
            print(f"   • Высокая вариация TTL: {len(high_var):,} записей")

# 3.5. Географические аномалии
print("\n🌍 ГЕОГРАФИЧЕСКИЕ АНОМАЛИИ:")
geo_cols = ['unique_country', 'unique_asn']
for col in geo_cols:
    if col in analysis_df.columns:
        # Много уникальных стран/ASN может быть признаком DGA
        many_unique = analysis_df[analysis_df[col] > analysis_df[col].quantile(0.95)]
        print(f"   • Много уникальных {col}: {len(many_unique):,} записей")

# 4. КОМПОЗИТНЫЙ АНАЛИЗ: Поиск самых подозрительных записей
print("\n" + "=" * 60)
print("🎯 ВЫЯВЛЕНИЕ САМЫХ ПОДОЗРИТЕЛЬНЫХ ЗАПИСЕЙ")
print("=" * 60)

# Создадим "балл подозрительности"
analysis_df['suspicion_score'] = 0

# Веса для разных аномалий
if 'NULL_frequency' in analysis_df.columns:
    analysis_df['suspicion_score'] += (analysis_df['NULL_frequency'] > analysis_df['NULL_frequency'].quantile(0.9)) * 2

if 'TXT_frequency' in analysis_df.columns:
    analysis_df['suspicion_score'] += (analysis_df['TXT_frequency'] > analysis_df['TXT_frequency'].quantile(0.9)) * 2

if 'entropy' in analysis_df.columns:
    analysis_df['suspicion_score'] += (analysis_df['entropy'] > analysis_df['entropy'].quantile(0.95)) * 3

if 'len' in analysis_df.columns:
    analysis_df['suspicion_score'] += (analysis_df['len'] > 63) * 2

if 'unique_country' in analysis_df.columns:
    analysis_df['suspicion_score'] += (analysis_df['unique_country'] > analysis_df['unique_country'].quantile(0.9)) * 1

# Классификация
analysis_df['is_suspicious'] = analysis_df['suspicion_score'] >= 3

# Статистика
suspicious_count = analysis_df['is_suspicious'].sum()
total_count = len(analysis_df)
suspicious_percent = (suspicious_count / total_count) * 100

print(f"🔍 Найдено подозрительных записей: {suspicious_count:,} из {total_count:,} ({suspicious_percent:.1f}%)")

# 5. СРАВНЕНИЕ С ИСХОДНЫМИ МЕТКАМИ (если есть)
if 'GlobalClass' in analysis_df.columns:
    print("\n" + "=" * 60)
    print("📊 СРАВНЕНИЕ С ИСХОДНЫМИ МЕТКАМИ")
    print("=" * 60)

    confusion_matrix = pd.crosstab(analysis_df['GlobalClass'], analysis_df['is_suspicious'])
    print("Матрица сопряженности:")
    print(confusion_matrix)

    # Эффективность наших эвристик
    if 'malicious' in analysis_df['GlobalClass'].values:
        malicious_total = (analysis_df['GlobalClass'] == 'malicious').sum()
        detected_malicious = ((analysis_df['GlobalClass'] == 'malicious') & analysis_df['is_suspicious']).sum()

        detection_rate = (detected_malicious / malicious_total) * 100 if malicious_total > 0 else 0

        print(f"\n📈 ЭФФЕКТИВНОСТЬ ОБНАРУЖЕНИЯ:")
        print(f"   Всего malicious: {malicious_total:,}")
        print(f"   Обнаружено нашими правилами: {detected_malicious:,}")
        print(f"   Эффективность обнаружения: {detection_rate:.1f}%")

# 6. ТОП ПОДОЗРИТЕЛЬНЫХ ЗАПИСЕЙ
print("\n" + "=" * 60)
print("🏆 ТОП-10 САМЫХ ПОДОЗРИТЕЛЬНЫХ ЗАПИСЕЙ")
print("=" * 60)

top_suspicious = analysis_df.sort_values('suspicion_score', ascending=False).head(10)

for i, (idx, row) in enumerate(top_suspicious.iterrows(), 1):
    print(f"\n{i}. [Счет подозрительности: {row['suspicion_score']}]")

    if 'rr' in row and pd.notna(row['rr']):
        print(f"   Домен: {row['rr']}")

    # Причины подозрительности
    reasons = []
    if 'NULL_frequency' in row and row['NULL_frequency'] > analysis_df['NULL_frequency'].quantile(0.9):
        reasons.append(f"высокая NULL частота ({row['NULL_frequency']:.3f})")
    if 'TXT_frequency' in row and row['TXT_frequency'] > analysis_df['TXT_frequency'].quantile(0.9):
        reasons.append(f"высокая TXT частота ({row['TXT_frequency']:.3f})")
    if 'entropy' in row and row['entropy'] > analysis_df['entropy'].quantile(0.95):
        reasons.append(f"высокая энтропия ({row['entropy']:.2f})")
    if 'len' in row and row['len'] > 63:
        reasons.append(f"длина {row['len']} символов")

    if reasons:
        print(f"   Причины: {', '.join(reasons)}")

    if 'GlobalClass' in row:
        print(f"   Исходная метка: {row['GlobalClass']}")

# 7. СОХРАНЕНИЕ РЕЗУЛЬТАТОВ
print("\n💾 Сохранение результатов...")

# Сохраняем все подозрительные записи
suspicious_df = analysis_df[analysis_df['is_suspicious']].copy()
suspicious_df.to_csv('suspicious_dns_records.csv', index=False, encoding='utf-8-sig')

# Сохраняем полный отчет с баллами
analysis_df.to_csv('full_dns_analysis.csv', index=False, encoding='utf-8-sig')

print(f"✅ Подозрительные записи сохранены: suspicious_dns_records.csv ({len(suspicious_df)} записей)")
print(f"✅ Полный анализ сохранен: full_dns_analysis.csv")

# 8. ВИЗУАЛИЗАЦИЯ
try:
    import matplotlib.pyplot as plt

    print("\n📈 Создание визуализаций...")

    fig, axes = plt.subplots(2, 3, figsize=(15, 10))

    # 1. Распределение suspicion_score
    ax1 = axes[0, 0]
    scores = analysis_df['suspicion_score'].value_counts().sort_index()
    ax1.bar(scores.index.astype(str), scores.values)
    ax1.set_title('Распределение баллов подозрительности')
    ax1.set_xlabel('Балл')
    ax1.set_ylabel('Количество записей')

    # 2. Энтропия у подозрительных/нормальных
    if 'entropy' in analysis_df.columns:
        ax2 = axes[0, 1]
        normal = analysis_df[~analysis_df['is_suspicious']]['entropy'].dropna()
        suspicious = analysis_df[analysis_df['is_suspicious']]['entropy'].dropna()
        ax2.boxplot([normal.values[:1000], suspicious.values[:1000]], labels=['Нормальные', 'Подозрительные'])
        ax2.set_title('Энтропия доменных имен')
        ax2.set_ylabel('Энтропия')

    # 3. Длина имен
    if 'len' in analysis_df.columns:
        ax3 = axes[0, 2]
        analysis_df['len'].hist(bins=50, alpha=0.7, ax=ax3)
        ax3.axvline(x=63, color='red', linestyle='--', label='RFC лимит (63)')
        ax3.set_title('Распределение длины имен')
        ax3.set_xlabel('Длина символов')
        ax3.set_ylabel('Частота')
        ax3.legend()

    # 4. NULL frequency
    if 'NULL_frequency' in analysis_df.columns:
        ax4 = axes[1, 0]
        analysis_df['NULL_frequency'].hist(bins=50, alpha=0.7, ax=ax4, log=True)
        ax4.set_title('Частота NULL запросов (лог шкала)')
        ax4.set_xlabel('Частота')
        ax4.set_ylabel('Частота (лог)')

    # 5. Сравнение с исходными метками
    if 'GlobalClass' in analysis_df.columns:
        ax5 = axes[1, 1]
        if 'malicious' in analysis_df['GlobalClass'].values:
            comparison = analysis_df.groupby('GlobalClass')['is_suspicious'].mean() * 100
            comparison.plot(kind='bar', ax=ax5, color=['green', 'red'])
            ax5.set_title('Процент подозрительных по классам')
            ax5.set_ylabel('% подозрительных')
            ax5.set_xticklabels(ax5.get_xticklabels(), rotation=0)

    # 6. TXT frequency
    if 'TXT_frequency' in analysis_df.columns:
        ax6 = axes[1, 2]
        analysis_df['TXT_frequency'].hist(bins=50, alpha=0.7, ax=ax6, log=True)
        ax6.set_title('Частота TXT запросов (лог шкала)')
        ax6.set_xlabel('Частота')
        ax6.set_ylabel('Частота (лог)')

    plt.tight_layout()
    plt.savefig('dns_features_analysis.png', dpi=150, bbox_inches='tight')
    plt.show()
    print("✅ Визуализация сохранена: dns_features_analysis.png")

except ImportError:
    print("ℹ️  Установите matplotlib для визуализации: pip install matplotlib")

print("\n✅ Анализ завершен!")