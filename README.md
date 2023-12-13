# tlspk-helper (In the process of moving this to Venafi CoolSolutions)

```
# on MacOS
brew install fsevents-tools

bucket=venafi-ecosystem-dev # drop the "-dev" as appropriate

while true; do
  notifywait .
  aws s3 cp v2/cfn-tlspk-cluster-bootstrapper.yaml  s3://${bucket}/tlspk/v2/
  aws s3 cp v2/tlspk-helper.sh                      s3://${bucket}/tlspk/v2/
done
```

Invoke as follows:
```
cd
bucket=venafi-ecosystem-dev # drop the "-dev" as appropriate
curl -fsSLO https://${bucket}.s3.amazonaws.com/tlspk/v1/tlspk-helper.sh && chmod 700 tlspk-helper.sh
./tlspk-helper.sh
```
