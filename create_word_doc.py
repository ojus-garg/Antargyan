import zipfile
import os

def generate_word_document(output_filepath):
    """
    Generate a clean, natively formatted Word Document (.docx) using Python standard library.
    Contains the 3 new technical features and slide breakdown.
    """

    content_types_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>'''

    package_rels_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>'''

    styles_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault>
      <w:rPr>
        <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>
        <w:sz w:val="22"/>
        <w:szCs w:val="22"/>
        <w:color w:val="333333"/>
      </w:rPr>
    </w:rPrDefault>
    <w:pPrDefault>
      <w:pPr>
        <w:spacing w:after="160" w:line="276" w:lineRule="auto"/>
      </w:pPr>
    </w:pPrDefault>
  </w:docDefaults>
</w:styles>'''

    document_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <!-- Document Title -->
    <w:p>
      <w:pPr>
        <w:pStyle w:val="Title"/>
        <w:jc w:val="center"/>
        <w:spacing w:before="240" w:after="120"/>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:b/>
          <w:sz w:val="44"/>
          <w:color w:val="1F4E78"/>
        </w:rPr>
        <w:t>Bitcoin Risk Analyzer &amp; Threat Intelligence Engine</w:t>
      </w:r>
    </w:p>

    <!-- Subtitle -->
    <w:p>
      <w:pPr>
        <w:jc w:val="center"/>
        <w:spacing w:before="0" w:after="360"/>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:i/>
          <w:sz w:val="24"/>
          <w:color w:val="595959"/>
        </w:rPr>
        <w:t>Technical Feature Breakdown &amp; Presentation Slide Notes</w:t>
      </w:r>
    </w:p>

    <!-- SECTION 1 -->
    <w:p>
      <w:pPr>
        <w:spacing w:before="300" w:after="140"/>
        <w:pBdr>
          <w:bottom w:val="single" w:sz="12" w:space="4" w:color="1F4E78"/>
        </w:pBdr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:b/>
          <w:sz w:val="32"/>
          <w:color w:val="1F4E78"/>
        </w:rPr>
        <w:t>1. Common-Input-Ownership Heuristic (CIOH) &amp; DSU Clustering</w:t>
      </w:r>
    </w:p>

    <w:p>
      <w:pPr><w:spacing w:before="100" w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="2E75B6"/></w:rPr><w:t>A. Conceptual Overview:</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:t>• In Bitcoin's Unspent Transaction Output (UTXO) accounting model, when a transaction spends multiple input addresses simultaneously in a single transaction, the same entity must hold and sign the private keys for all those inputs.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:t>• CIOH groups individual disparate Bitcoin addresses into a unified "Entity Wallet Cluster", enabling forensic investigators to de-anonymize criminal syndicates rather than analyzing single isolated addresses.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:t>• Threat Inheritance: If an unflagged, clean wallet co-spends transaction inputs with a known criminal or sanctioned address (e.g., Lazarus Group, LockBit, OFAC SDN), the entire cluster inherits threat attribution and triggers a hard risk floor (Risk Score ≥ 95.0/100).</w:t></w:r>
    </w:p>

    <w:p>
      <w:pPr><w:spacing w:before="120" w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="2E75B6"/></w:rPr><w:t>B. Technical Architecture &amp; Algorithms:</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>• Data Structure: </w:t></w:r>
      <w:r><w:t>Implemented using Disjoint-Set Union (DSU / Union-Find) with recursive Path Compression and Union-by-Rank.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>• Algorithmic Complexity: </w:t></w:r>
      <w:r><w:t>Achieves nearly linear O(α(N)) amortized time complexity per find/union operation via the Inverse Ackermann function α(N).</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>• On-Chain Graph Traversal: </w:t></w:r>
      <w:r><w:t>Recursively scans multi-input transactions across multi-hop subgraphs to cluster associated addresses without manual entity tagging.</w:t></w:r>
    </w:p>

    <w:p>
      <w:pPr><w:spacing w:before="120" w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="2E75B6"/></w:rPr><w:t>C. Ready-to-Use PPT Bullet Points:</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>✔ UTXO Entity De-Anonymization: </w:t></w:r>
      <w:r><w:t>Applies Common-Input-Ownership Heuristic (CIOH) to merge co-spent multi-input addresses into unified entities.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>✔ High-Performance DSU: </w:t></w:r>
      <w:r><w:t>Leverages Union-Find with Path Compression and Union-by-Rank for real-time O(α(N)) graph partitioning.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="140"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>✔ Criminal Co-Spending Propagation: </w:t></w:r>
      <w:r><w:t>Automatically attributes sanctions and state-sponsored cybercrime to unlisted accomplice wallets sharing transaction inputs.</w:t></w:r>
    </w:p>

    <!-- SECTION 2 -->
    <w:p>
      <w:pPr>
        <w:spacing w:before="300" w:after="140"/>
        <w:pBdr>
          <w:bottom w:val="single" w:sz="12" w:space="4" w:color="1F4E78"/>
        </w:pBdr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:b/>
          <w:sz w:val="32"/>
          <w:color w:val="1F4E78"/>
        </w:rPr>
        <w:t>2. CoinJoin Collaborative Mixing Exemption Filter</w:t>
      </w:r>
    </w:p>

    <w:p>
      <w:pPr><w:spacing w:before="100" w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="2E75B6"/></w:rPr><w:t>A. Conceptual Overview:</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:t>• Standard CIOH breaks on CoinJoin transactions (e.g., Wasabi Wallet, Samourai Whirlpool), where multiple independent users intentionally combine their UTXOs into a single multi-party transaction to gain privacy.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:t>• Naive clustering algorithms would mistakenly merge all CoinJoin participants into a single entity, falsely associating innocent users with criminals or tainted addresses.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:t>• Our intelligent CoinJoin filter detects collaborative mixing signatures and exempts these transactions from CIOH clustering to preserve zero false-positive integrity.</w:t></w:r>
    </w:p>

    <w:p>
      <w:pPr><w:spacing w:before="120" w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="2E75B6"/></w:rPr><w:t>B. Technical Architecture &amp; Algorithms:</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>• Equal-Denomination Frequency Analysis: </w:t></w:r>
      <w:r><w:t>Scans output satoshi values using frequency histograms to verify if ≥ 3 outputs share the exact same value (e.g., 0.01000000 BTC, 0.05000000 BTC standard mixing pools).</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>• Multi-Party Thresholds: </w:t></w:r>
      <w:r><w:t>Requires ≥ 3 distinct inputs and ≥ 3 distinct outputs matching mixing pool topology.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>• DSU Bypass: </w:t></w:r>
      <w:r><w:t>Whenever is_coinjoin_tx returns True, input union operations are strictly bypassed and recorded as a filtered CoinJoin event.</w:t></w:r>
    </w:p>

    <w:p>
      <w:pPr><w:spacing w:before="120" w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="2E75B6"/></w:rPr><w:t>C. Ready-to-Use PPT Bullet Points:</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>✔ CoinJoin False-Positive Shield: </w:t></w:r>
      <w:r><w:t>Prevents erroneous entity clustering across privacy protocols (Wasabi, Samourai Whirlpool).</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>✔ Equal-Denomination Value Matching: </w:t></w:r>
      <w:r><w:t>Identifies collaborative mixing patterns via statistical satoshi output distribution analysis.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="140"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>✔ Forensic Precision: </w:t></w:r>
      <w:r><w:t>Protects innocent third-party participants from inheriting illicit taint during collaborative coin mixing.</w:t></w:r>
    </w:p>

    <!-- SECTION 3 -->
    <w:p>
      <w:pPr>
        <w:spacing w:before="300" w:after="140"/>
        <w:pBdr>
          <w:bottom w:val="single" w:sz="12" w:space="4" w:color="1F4E78"/>
        </w:pBdr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:b/>
          <w:sz w:val="32"/>
          <w:color w:val="1F4E78"/>
        </w:rPr>
        <w:t>3. Autonomous Unlabeled Exchange Hot Wallet Discovery</w:t>
      </w:r>
    </w:p>

    <w:p>
      <w:pPr><w:spacing w:before="100" w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="2E75B6"/></w:rPr><w:t>A. Conceptual Overview:</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:t>• Static databases only track a small fraction of active exchanges and OTC liquidity desks. New, regional, or unlabeled exchanges often get misidentified as high-risk money-laundering mixers due to high transaction counts.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:t>• We created a behavioral classification engine that analyzes on-chain topological flow patterns to automatically recognize commercial liquidity hubs without requiring them to be in a hardcoded database.</w:t></w:r>
    </w:p>

    <w:p>
      <w:pPr><w:spacing w:before="120" w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="2E75B6"/></w:rPr><w:t>B. Technical Architecture &amp; Algorithms:</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>• Liquidity Turnover &amp; Float Ratio: </w:t></w:r>
      <w:r><w:t>Measures the continuous liquidation ratio (Spent BTC / Funded BTC). Active exchanges maintain a dynamic float between 0.65 and 0.999 while handling high transaction counts (50 to 500+ txs) and high cumulative volume (2 to 50+ BTC).</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>• Bidirectional Flow Symmetry: </w:t></w:r>
      <w:r><w:t>Evaluates continuous deposit consolidation (fan-in) and withdrawal fulfillment (fan-out).</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="100"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>• False Mixer Alert Suppression: </w:t></w:r>
      <w:r><w:t>Automatically suppresses mixer/tumbler warnings when exchange confidence ≥ 65%, classifying the node as "autonomous exchange hot wallet / commercial liquidity hub" with low risk.</w:t></w:r>
    </w:p>

    <w:p>
      <w:pPr><w:spacing w:before="120" w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="2E75B6"/></w:rPr><w:t>C. Ready-to-Use PPT Bullet Points:</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>✔ Dynamic Entity Discovery: </w:t></w:r>
      <w:r><w:t>Identifies unlisted exchange hot wallets and OTC desks using behavioral graph topology instead of static lists.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>✔ Macro Turnover &amp; Float Analysis: </w:t></w:r>
      <w:r><w:t>Analyzes transaction velocity and liquidity turnover ratios (65% to 99.9%).</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="140"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>✔ False-Alert Mitigation: </w:t></w:r>
      <w:r><w:t>Prevents commercial hubs from being misflagged as illicit mixers, automatically assigning safe, low-risk classifications.</w:t></w:r>
    </w:p>

    <!-- SUMMARY TABLE -->
    <w:p>
      <w:pPr>
        <w:spacing w:before="300" w:after="140"/>
        <w:pBdr>
          <w:bottom w:val="single" w:sz="12" w:space="4" w:color="1F4E78"/>
        </w:pBdr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:b/>
          <w:sz w:val="32"/>
          <w:color w:val="1F4E78"/>
        </w:rPr>
        <w:t>4. Summary Matrix (For PPT Conclusion Slide)</w:t>
      </w:r>
    </w:p>

    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>1. CIOH Entity Clustering: </w:t></w:r>
      <w:r><w:t>Solves wallet fragmentation | Uses Disjoint-Set Union (DSU) with Path Compression | Enables syndicate-level threat propagation.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="80"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>2. CoinJoin Exemption: </w:t></w:r>
      <w:r><w:t>Solves collaborative mixing false positives | Uses equal-denomination histogram analysis | Preserves forensic accuracy for privacy users.</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:ind w:left="360"/><w:spacing w:after="140"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="1F4E78"/></w:rPr><w:t>3. Autonomous Exchange Discovery: </w:t></w:r>
      <w:r><w:t>Solves unlabeled exchange misclassification | Uses liquidity turnover float (0.65-0.999) &amp; flow symmetry | Eliminates false mixer warnings.</w:t></w:r>
    </w:p>

    <w:sectPr>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/>
    </w:sectPr>
  </w:body>
</w:document>'''

    # Package files into .docx zip
    with zipfile.ZipFile(output_filepath, 'w', compression=zipfile.ZIP_DEFLATED) as docx:
        docx.writestr('[Content_Types].xml', content_types_xml)
        docx.writestr('_rels/.rels', package_rels_xml)
        docx.writestr('word/document.xml', document_xml)
        docx.writestr('word/styles.xml', styles_xml)

    print(f"Successfully generated: {output_filepath}")

if __name__ == "__main__":
    out_path = os.path.join(r"C:\Users\hp\Desktop\python\AI Agent", "Bitcoin_Risk_Analyzer_PPT_Notes.docx")
    generate_word_document(out_path)
