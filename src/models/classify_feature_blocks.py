"""
    EMBER 500개 특징 인덱스를 thrember features.py 소스에서 확인한 정확한 블록 경계값으로 분류한다.
    재학습 불필요, top_feature_indices_500.npy만 있으면 바로 실행 가능하다.
    
    블록 경계값은 thrember/features.py의 PEFeatureExtractor OrderedDict 순서와 
    각 FeatureType 클래스의 dim을 그대로 누적해서 계산한 것이며, 총합이 2568임을 확인했다. 
"""

import numpy as np
import pandas as pd

# ==================================================================
# 블록 경계값 ㅡ thrember/features.py 소스 기준 정확한 값
# (start, end): 해당 특징 인덱스 범위 [start, end)
# ==================================================================
BLOCK_RANGES = {
    "GeneralFileInfo": (0, 7),
    "ByteHistogram": (7, 263),
    "ByteEntropyHistogram": (263, 519),
    "StringExtractor": (519, 696),
    "HeaderFileInfo": (696, 770),
    
    # SectionInfo 내부 세부 블록 (일부만 해싱)
    "SectionInfo_general": (770, 781),          # 해싱 안 됨 (max/min entropy 등)
    "SectionInfo_sizes_hashed": (781, 831),      # 해싱됨
    "SectionInfo_vsize_hashed": (831, 881),      # 해싱됨
    "SectionInfo_entropy_hashed": (881, 931),    # 해싱됨
    "SectionInfo_characteristics_hashed": (931, 981),  # 해싱됨
    "SectionInfo_entry_name_hashed": (981, 991), # 해싱됨
    "SectionInfo_overlay": (991, 994),           # 해싱 안 됨
    
    # ImportsInfo 내부 세부 블록
    "ImportsInfo_lengths": (994, 996),           # 해싱 안 됨 (import/library 개수)
    "ImportsInfo_libraries_hashed": (996, 1252), # 해싱됨
    "ImportsInfo_imports_hashed": (1252, 2276),  # 해싱됨
    
    # ExportsInfo 내부 세부 블록
    "ExportsInfo_length": (2276, 2277),          # 해싱 안 됨
    "ExportsInfo_hashed": (2277, 2405),          # 해싱됨
    "DataDirectories": (2405, 2439),
    
    # RichHeader 내부 세부 블록
    "RichHeader_count": (2439, 2440),            # 해싱 안 됨
    "RichHeader_hashed": (2440, 2472),           # 해싱됨
    "AuthenticodeSignature": (2472, 2480),
    "PEFormatWarnings": (2480, 2568),
}


HASHED_BLOCKS = {
    "SectionInfo_sizes_hashed", "SectionInfo_vsize_hashed",
    "SectionInfo_entropy_hashed", "SectionInfo_characteristics_hashed",
    "SectionInfo_entry_name_hashed",
    "ImportsInfo_libraries_hashed", "ImportsInfo_imports_hashed",
    "ExportsInfo_hashed", "RichHeader_hashed",
}

# 검산: 전체 합이 2568
_total = max(end for _, end in BLOCK_RANGES.values())
assert _total == 2568, f"경계값 오류: 총합 {_total} != 2568"

def classify(idx: int) -> tuple[str, bool]:
    for block, (start, end) in BLOCK_RANGES.items():
        if start <= idx < end:
            return block, block in HASHED_BLOCKS
    return "Unknown", None

def main():
    top_500 = np.load(r"C:\Users\jyoon\trust-triage\top_feature_indices_500.npy")
    
    results = [classify(idx) for idx in top_500]
    blocks = [r[0] for r in results]
    is_hashed = [r[1] for r in results]
    
    df = pd.DataFrame({"index": top_500, "block": blocks, "is_hashed": is_hashed})
    
    print("========= 블록별 분포 =========")
    print(df["block"].value_counts())
    print()
    print(f"해싱 안된 특징: {(~df['is_hashed']).sum()}개")
    print(f"해싱된 특징: {(df['is_hashed']).sum()}개")
    
    
    df.to_csv("top500_block_classification.csv", index=False)
    print("\nCSV 저장됨\n")
    
    
if __name__ == "__main__":
    main()