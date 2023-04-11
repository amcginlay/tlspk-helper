# tlspk-helper

```
# on MacOS
brew install fsevents-tools

bucket=venafi-ecosystem-dev # drop the "-dev" as appropriate
while true; do
  notifywait ./tlspk-helper.sh
  echo "uploading tlspk-helper.sh"
  aws s3 cp tlspk-helper.sh s3://${bucket}/tlspk/tlspk-helper.sh
done
```

Invoke as follows:
```
cd
curl -fsSL -o tlspk-helper.sh https://${bucket}.s3.amazonaws.com/tlspk/tlspk-helper.sh && chmod 700 tlspk-helper.sh
./tlspk-helper.sh
```
