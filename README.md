# tlspk-helper

```
# on MacOS
brew install fsevents-tools

while true
  do notifywait ./tlspk-helper.sh
  echo "uploading tlspk-helper.sh"
  aws s3 cp tlspk-helper.sh s3://venafi-tlspk/
done
```

Invoke as follows:
```
curl -fsSL -o tlspk-helper.sh https://venafi-tlspk.s3.us-west-2.amazonaws.com/tlspk-helper.sh && chmod 700 tlspk-helper.sh
./tlspk-helper.sh
```
