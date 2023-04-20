# tlspk-helper

```
# on MacOS
brew install fsevents-tools

bucket=venafi-ecosystem-dev # drop the "-dev" as appropriate

while true; do
  notifywait .
  echo "uploading tlspk-helper.sh"
  # aws s3 cp cfn-tlspk-cluster-bootstrapper.yaml    s3://${bucket}/tlspk/
  aws s3 cp tlspk-helper.sh                        s3://${bucket}/tlspk/
  # aws s3 cp tlspk-helper.README.txt                s3://${bucket}/tlspk/
  # aws s3 cp tlspk-disconnect-all-clusters.sh       s3://${bucket}/tlspk/
  # aws s3 cp tlspk-delete-all-image-pull-secrets.sh s3://${bucket}/tlspk/
done
```

Invoke as follows:
```
cd
bucket=venafi-ecosystem-dev # drop the "-dev" as appropriate
curl -fsSL -o tlspk-helper.sh https://${bucket}.s3.amazonaws.com/tlspk/tlspk-helper.sh && chmod 700 tlspk-helper.sh
./tlspk-helper.sh
```
