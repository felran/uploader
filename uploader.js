import * as SparkMD5 from 'spark-md5';
import request from './request';
import Serialize from './serialize';

const NOSUP = 'https://nosup-eastchina1.126.net';
const ERRORMSG = {
    1000:'文件对象不存在',
    1001:'文件大小超限',
    1002:'格式不满足',
    1003:'网络异常',
    1004:'NOS校验失败'
};
const FILE_STATUS ={
    WAIT:0,
    PROGRESS:1,
    SUCCESS:2,
    ERROR:3
};
class Uploader{
    constructor(options={}){
        const defaultOption = {
            host:'',                      // 上传服务器的地址
            trunkSize:4*1024*1024,       // 每个分片大小，默认4M
            limitSize:100*1024*1024,     // 文件大小限制,默认100M
            fileExts:'*',                // 允许文件上传格式,* 表示允许上传任意格式:['JPG','JPEG','PNG','BMP']
            file:'',                     // 文件对象
            getSignUrl:'',                 // 获取签名
            formUploadParams:{},           // 传入该参数代表form表单直传，其他分片上传参数将无效
            uploadProgress(){},
            uploadSuccess(){},
            uploadError(){},
            md5Progress(){} 
        };
        this.options = Object.assign({},defaultOption,options);
        this.file = this.options.file;
        this.fileObj = {
            key:`${this.file.name}_${new Date().getTime()}`,
            file:this.file,
            name:this.file.name,
            size:this.file.size,
            status:FILE_STATUS.WAIT,
            progress:0
        };
        this.fileStatus = FILE_STATUS.WAIT;            // 0:待上传,1:上传中,2:上传成功,3:上传失败
        this.uploadProgress = this.options.uploadProgress;
        this.uploadSuccess = this.options.uploadSuccess;
        this.uploadError = this.options.uploadError;
        this.md5Progress = this.options.md5Progress;
    }

    setStatus(status){
        this.fileStatus = status;
        this.fileObj.status = status;
    }

    // 检查文件格式
    checkField(){
        // 初始化校验
        // const file = this.file;
        const suffix = this.file.name.split('.').pop();
        switch(true){
            case !this.file:
                this.setStatus(FILE_STATUS.ERROR);
                this.uploadError(this.fileObj,1000,ERRORMSG['1000']);
                return false;
            case this.file.size>this.options.limitSize:
                this.setStatus(FILE_STATUS.ERROR);
                this.uploadError(this.fileObj,1001,ERRORMSG['1001']);
                return false; 
            case this.options.fileExts!=='*'&&!this.options.fileExts.includes(suffix.toUpperCase())||this.file.name===suffix:
                this.setStatus(FILE_STATUS.ERROR);
                this.uploadError(this.fileObj,1002,ERRORMSG['1002']);
                return false; 
            default:
                return true;
        }
    }

    // 文件MD5值计算
    checkMD5(){
        if(this.fileMD5) return Promise.resolve(this.fileMD5);
        return new Promise((resolve,reject)=>{
            const blobSlice = File.prototype.slice || File.prototype.mozSlice || File.prototype.webkitSlice;
		    const chunkSize = 2*1024*1024;
            let currentChunk = 0;
            const spark = new SparkMD5.ArrayBuffer();
            const fileReader = new FileReader();
            const chunks = Math.ceil(this.file.size / chunkSize);
            const loadNext = ()=>{
                const start = currentChunk * chunkSize;
                const end = ((start + chunkSize) >= this.file.size) ? this.file.size : start + chunkSize;
                fileReader.readAsArrayBuffer(blobSlice.call(this.file, start, end));
            };
            fileReader.onload =  e => {
                spark.append(e.target.result);
                currentChunk += 1;	
                let progress = 1;
                if(chunks !==0){
                    progress = currentChunk/chunks;
                }
                this.md5Progress(this.fileObj,progress);                                    
                if (currentChunk < chunks) {
                    loadNext();
                } else {
                    const md5= spark.end();
                    this.fileMD5 = md5;
                    resolve(md5);
                }
            };
            fileReader.onerror=()=>{
                reject();
            };
            loadNext();
        });
    }
    
    // 获取文件偏移量，断点续传
    getOffset(token){
        const context = localStorage.getItem(`${this.fileMD5}_context`);
        const name = localStorage.getItem(`${this.fileMD5}_objectName`);
        if(!context||!name) return Promise.resolve({offset:0});
        const params = Serialize({version:'1.0',context});
        this.uploadFileName = name;
        return request(`${NOSUP}/${this.bucket}/${name}?uploadContext&${params}`,{
            credentials: 'omit',
            headers:{'x-nos-token':token}
        });
    }

    /**
     * 获取文件nos-token
     * 断点续传 x-nos-token 需通过上一次上传的文件名生成
     * 关键变量：Access Key ,Access Secret
     * 1.encodePolicy=base64_encode{Bucket:'',Object:'',Expires:}
     * 2.sign=hmac_sha256(encodePolicy,'<Access Secret>')
     * 3.encodeSign=base64_encode(sign)
     * 4.x-nos-token=UPLOAD Access Key:encodeSign:encodePolicy
     * @todo 改进，断点续传需服务端接受参数ObjectName(上一次上传的文件名),重新生成token
     */

    getSign(){ 
        const {getSignUrl} = this.options;  // getNosToken from server
        if(!getSignUrl) {
            return new Error('token不能为空');
        };
        const context = localStorage.getItem(`${this.fileMD5}_context`);
        const object = localStorage.getItem(`${this.fileMD5}_objectName`);
        // return new Promise((resolve,reject)=>{
        return request(getSignUrl,{
                method:'POST',
                body:{
                        uploadType:this.options.uploadType,
                        object:context&&object,
                        originName:this.file.name
                    }
            }).then(data=>{
                if(data.code===200){
                    return data.result;   
                }
                this.setStatus(FILE_STATUS.ERROR);
                this.uploadError(this.fileObj,data.code,data.msg);
                return false;
            });
        // });
        
    }

    // 开始上传
    init(){
        const {formUploadParams} = this.options;
        if(!this.checkField()) return;
        if(Object.keys(formUploadParams).length===0){
            this.uploadPart();
        }else{
            this.uploadForm(formUploadParams);
        }
    }

    // 表单上传
    uploadForm(params){
        if(Object.keys(params).length===0) return;
        const formData = new FormData();
        Object.keys(params).forEach(key=>{
            formData.append(key,params[key]);
        });
        formData.append('file',this.file,this.file.name);
        const xhr = new XMLHttpRequest();
        xhr.upload.onprogress = e => {
            let progress = 0;
            if (e.lengthComputable) {
                progress = e.loaded / this.file.size;
                if(progress > 0 && progress <= 1){
                    this.setStatus(FILE_STATUS.PROGRESS)
                };
                this.fileObj.progress = progress;
                this.uploadProgress(this.fileObj,progress);
            }
        };
        xhr.onreadystatechange = ()=>{
            if (xhr.readyState !== 4) return;
            if (xhr.status&&xhr.status === 200) {
                this.setStatus(FILE_STATUS.SUCCESS);
                this.uploadSuccess(this.fileObj);
            }  
        };
        xhr.open("POST", this.options.host);
        xhr.send(formData);
    }

    // 分片上传
    async uploadPart(){
        await this.checkMD5();
        const data = await this.getSign();
        const token = {data};
        this.uploadFileName = data.object;
        this.bucket = data.bucket;
        const offset = await this.getOffset(token);
        this.trunkOffset = offset.offset;
        /**
         * directUpload 是否秒传，若是，直接调用uploadSuccess,若否，上传至NOS服务器
         * @todo 如何知道当前文件上传完成(uploadSuccess执行完成)，需uploadSuccess改写为promise
         */
        if(data.directUpload==='true'){
            this.fileObj.token = token;
            this.setStatus(FILE_STATUS.SUCCESS);  
            this.uploadSuccess(this.fileObj);
        }else{
            this.upload(token);
        }
    }

    // 开始上传
    upload(token){
        this.trunkOffset = this.trunkOffset||0;
        if(!this.xhr){
            this.xhr = new XMLHttpRequest()
        };
        const {xhr} = this;
        xhr.upload.onprogress = e => {
            let progress = 0;
            if (e.lengthComputable) {
                progress = (this.trunkOffset + e.loaded) / this.file.size;
                if(progress > 0 && progress <= 1){
                    this.setStatus(FILE_STATUS.PROGRESS)
                };
                this.fileObj.progress = progress;
                this.uploadProgress(this.fileObj,progress);
            }
        };
        xhr.onreadystatechange = ()=>{
            if (xhr.readyState !== 4) return;
            if (xhr.status&&xhr.status === 200) {
                let result = {};
                try{
                    result = JSON.parse(xhr.responseText);
                }catch(e){
                    throw new Error('upload parse response error',e);
                }
                result.context = `${result.context}`;
                // 记录context,便于断点续传
                if(result.context!=='undefined'&&result.context!=='null'){
                    localStorage.setItem(`${this.fileMD5}_context`, result.context);
                    localStorage.setItem(`${this.fileMD5}_objectName`, this.uploadFileName);
                }
                if(result.offset<this.file.size){
                    this.trunkOffset = result.offset;
                    this.upload(token);       
                }else if(result.offset>=this.file.size){
                    localStorage.removeItem(`${this.fileMD5}_context`);
                    localStorage.removeItem(`${this.fileMD5}_objectName`);
                    this.fileObj.token = token;
                    this.setStatus(FILE_STATUS.SUCCESS);
                    this.uploadSuccess(this.fileObj);
                }
            }  
        };
        const trunkEnd = this.trunkOffset+this.options.trunkSize;
        const complete = trunkEnd >= this.file.size;
        let context = localStorage.getItem(`${this.fileMD5}_context`);
        context = context?`&context=${context}`:'';
        const xhrParam = `?offset=${this.trunkOffset}&complete=${complete}${context}&version=1.0`; 
        xhr.open('post',`${NOSUP}/${this.bucket}/${encodeURIComponent(this.uploadFileName)}${xhrParam}`);
        xhr.setRequestHeader('x-nos-token', token);
        xhr.send(this.file.slice(this.trunkOffset, trunkEnd));
    }

    // // 重新上传
    // reupload(){

    // }

    // 取消上传
    abort(){
        if(this.xhr){
            this.xhr.upload.onprogress = undefined;
            this.xhr.onreadystatechange = undefined;
            this.xhr.abort();
            this.xhr = undefined;
        }
        this.setStatus(FILE_STATUS.ERROR);
    }

    getStatus(){
        return this.fileStatus;
    }
}
export default Uploader;