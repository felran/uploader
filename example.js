import Crypto from './utils/crypto';
import Base64 from './utils/base64';
import Uploader from './uploader';
const accessid = 'youOSSId';
const accesskey = 'youOSSKey';
const fileInputChange = (e) => {
    const { files } = e.target;
    this.uploadImg(files, {});
};

const uploadImg = (files, { uploadProgress, uploadSuccess }) => {
    const fileArray = Array.from(files);
    const policyText = {
      expiration: '2020-01-01T12:00:00.000Z', // 设置该Policy的失效时间，超过这个失效时间之后，就没有办法通过这个policy上传文件了
      conditions: [
        ['content-length-range', 0, 1048576000], // 设置上传文件的大小限制
      ],
    };
    const policyBase64 = Base64.encode(JSON.stringify(policyText));
    const bytes = Crypto.HMAC(Crypto.SHA1, policyBase64, accesskey, { asBytes: true });
    const signature = Crypto.util.bytesToBase64(bytes);
    const that = this;
    fileArray.forEach(file => {
      new Uploader({
        host,
        file,
        uploadProgress: uploadProgress || that.uploadProgress,
        uploadSuccess: uploadSuccess || that.uploadSuccess,
        formUploadParams: {
          name: file.name,
          key: file.name,
          policy: policyBase64,
          OSSAccessKeyId: accessid,
          success_action_status: '200', // 让服务端返回200,不然，默认会返回204
          signature,
        },
      }).init();
    });
  };

  // 上传进度
const  uploadProgress = (fileObj, progress) => {
    console.log(progress);
  };

  // 上传成功
const  uploadSuccess = fileObj => {
    console.log('success');
};