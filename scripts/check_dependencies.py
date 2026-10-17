"""Query OSV's RustSec-backed database using exact Cargo.lock versions."""
import datetime, json, pathlib, tomllib, urllib.request
root=pathlib.Path(__file__).resolve().parents[1]
lock=tomllib.loads((root/'Cargo.lock').read_text())
packages=[p for p in lock['package'] if p.get('source','').startswith('registry+')]
queries=[{'package':{'name':p['name'],'ecosystem':'crates.io'},'version':p['version']} for p in packages]
req=urllib.request.Request('https://api.osv.dev/v1/querybatch',data=json.dumps({'queries':queries}).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(req,timeout=60) as response: result=json.load(response)
report={'checked_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':'https://api.osv.dev/v1/querybatch','packages':[]}
for p,r in zip(packages,result['results'],strict=True):
 report['packages'].append({'name':p['name'],'version':p['version'],'vulnerabilities':r.get('vulns',[])})
(root/'docs').mkdir(exist_ok=True)
(root/'docs'/'dependency-audit.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
findings=[p for p in report['packages'] if p['vulnerabilities']]
print(json.dumps({'checked_packages':len(packages),'findings':findings},indent=2))
raise SystemExit(1 if findings else 0)
