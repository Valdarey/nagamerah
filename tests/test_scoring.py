from nagamerah.analysis.scoring import verdict
def test_verdicts(): assert verdict(None)=='Unknown'; assert verdict(5)=='No Detection'; assert verdict(45)=='Suspicious'; assert verdict(85)=='Malicious'
