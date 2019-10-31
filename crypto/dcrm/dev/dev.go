// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dev 

import (
    "github.com/fusion/go-fusion/crypto/secp256k1"
    "github.com/fusion/go-fusion/crypto/dcrm/dev/lib"
    "math/big"
    "strconv"
    "strings"
    "fmt"
    "time"
    "encoding/json"
    "container/list"
    "bytes"
    "compress/zlib"
    "encoding/hex"
    "io"
    "os"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/fusion/go-fusion/crypto/sha3"
    "github.com/fusion/go-fusion/internal/common/hexutil"
    "sort"
    "runtime"
    "path/filepath"
    "sync"
    "os/user"
    "math/rand"
)

var (
    Sep = "dcrmparm"
    SepSave = "dcrmsepsave"
    SepSg = "dcrmmsg"
    SepDel = "dcrmsepdel"

    PaillierKeyLength = 2048
    sendtogroup_lilo_timeout = 80 
    sendtogroup_timeout = 80
    ch_t = 60

    //callback
    GetGroup func(string) (int,string)
    SendToGroupAllNodes func(string,string) string
    GetSelfEnode func() string
    BroadcastInGroupOthers func(string,string)
    SendToPeer func(string,string) error
    ParseNode func(string) string
)

func RegP2pGetGroupCallBack(f func(string)(int,string)) {
    GetGroup = f
}

func RegP2pSendToGroupAllNodesCallBack(f func(string,string)string) {
    SendToGroupAllNodes = f
}

func RegP2pGetSelfEnodeCallBack(f func()string) {
    GetSelfEnode = f
}

func RegP2pBroadcastInGroupOthersCallBack(f func(string,string)) {
    BroadcastInGroupOthers = f
}

func RegP2pSendMsgToPeerCallBack(f func(string,string)error) {
    SendToPeer = f
}

func RegP2pParseNodeCallBack(f func(string)string) {
    ParseNode = f
}

func PutGroup(groupId string) bool {
    if groupId == "" {
	return false
    }

    lock.Lock()
    dir := GetGroupDir()
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil {
	lock.Unlock()
	return false
    }

    var data string
    var b bytes.Buffer 
    b.WriteString("") 
    b.WriteByte(0) 
    b.WriteString("") 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	key := string(iter.Key())
	value := string(iter.Value())
	if strings.EqualFold(key,"GroupIds") {
	    data = value
	    break
	}
    }
    iter.Release()
    ///////
    if data == "" {
	db.Put([]byte("GroupIds"),[]byte(groupId),nil)
	db.Close()
	lock.Unlock()
	return true 
    }

    m := strings.Split(data,":")
    for _,v := range m {
	if strings.EqualFold(v,groupId) {
	    db.Close()
	    lock.Unlock()
	    return true 
	}
    }

    data += ":" + groupId
    db.Put([]byte("GroupIds"),[]byte(data),nil)
   
    db.Close()
    lock.Unlock()
    return true
}

func InitDev(groupId string) {
    cur_enode = GetSelfEnode()
    if !PutGroup(groupId) {
	return
    }

    fmt.Println("=========InitDev===========","groupId",groupId)
    peerscount, _ := GetGroup(groupId)
   NodeCnt = peerscount
   Enode_cnts = peerscount //bug
    GetEnodesInfo()
}

////////////////////////dcrm///////////////////////////////
var (
    //rpc-req //dcrm node
    RpcMaxWorker = 10000 
    RpcMaxQueue  = 10000
    RpcReqQueue chan RpcReq 
    workers []*RpcReqWorker
    //rpc-req
    cur_enode string
    Enode_cnts int
    NodeCnt = 3
    ThresHold = 3
    lock5 sync.Mutex
    lock sync.Mutex
)

type RpcDcrmRes struct {
    Ret string
    Err error
}

type RpcReq struct {
    rpcdata WorkReq
    ch chan interface{}
}

//rpc-req
type ReqDispatcher struct {
    // A pool of workers channels that are registered with the dispatcher
    WorkerPool chan chan RpcReq
}

type RpcReqWorker struct {
    RpcReqWorkerPool  chan chan RpcReq
    RpcReqChannel  chan RpcReq
    rpcquit        chan bool
    id int
    groupid string
    ch chan interface{}
    retres *list.List
    //
    msg_c1 *list.List
    splitmsg_c1 map[string]*list.List
    
    msg_kc *list.List
    splitmsg_kc map[string]*list.List
    
    msg_mkg *list.List
    splitmsg_mkg map[string]*list.List
    
    msg_mkw *list.List
    splitmsg_mkw map[string]*list.List
    
    msg_delta1 *list.List
    splitmsg_delta1 map[string]*list.List
    
    msg_d1_1 *list.List
    splitmsg_d1_1 map[string]*list.List
    
    msg_share1 *list.List
    splitmsg_share1 map[string]*list.List
    
    msg_zkfact *list.List
    splitmsg_zkfact map[string]*list.List
    
    msg_zku *list.List
    splitmsg_zku map[string]*list.List
    
    msg_mtazk1proof *list.List
    splitmsg_mtazk1proof map[string]*list.List
    
    msg_c11 *list.List
    splitmsg_c11 map[string]*list.List
    
    msg_d11_1 *list.List
    splitmsg_d11_1 map[string]*list.List
    
    msg_s1 *list.List
    splitmsg_s1 map[string]*list.List
    
    msg_ss1 *list.List
    splitmsg_ss1 map[string]*list.List

    pkx *list.List
    pky *list.List
    save *list.List
    
    bc1 chan bool
    bmkg chan bool
    bmkw chan bool
    bdelta1 chan bool
    bd1_1 chan bool
    bshare1 chan bool
    bzkfact chan bool
    bzku chan bool
    bmtazk1proof chan bool
    bkc chan bool
    bs1 chan bool
    bss1 chan bool
    bc11 chan bool
    bd11_1 chan bool

    sid string //save the txhash

    //ed
    bedc11 chan bool
    msg_edc11 *list.List
    bedzk chan bool
    msg_edzk *list.List
    bedd11 chan bool
    msg_edd11 *list.List
    bedshare1 chan bool
    msg_edshare1 *list.List
    bedcfsb chan bool
    msg_edcfsb *list.List
    edsave *list.List
    edpk *list.List
    
    bedc21 chan bool
    msg_edc21 *list.List
    bedzkr chan bool
    msg_edzkr *list.List
    bedd21 chan bool
    msg_edd21 *list.List
    bedc31 chan bool
    msg_edc31 *list.List
    bedd31 chan bool
    msg_edd31 *list.List
    beds chan bool
    msg_eds *list.List

}

//workers,RpcMaxWorker,RpcReqWorker,RpcReqQueue,RpcMaxQueue,ReqDispatcher
func InitChan() {
    workers = make([]*RpcReqWorker,RpcMaxWorker)
    RpcReqQueue = make(chan RpcReq,RpcMaxQueue)
    reqdispatcher := NewReqDispatcher(RpcMaxWorker)
    reqdispatcher.Run()
}

func NewReqDispatcher(maxWorkers int) *ReqDispatcher {
    pool := make(chan chan RpcReq, maxWorkers)
    return &ReqDispatcher{WorkerPool: pool}
}

func (d *ReqDispatcher) Run() {
// starting n number of workers
    for i := 0; i < RpcMaxWorker; i++ {
	worker := NewRpcReqWorker(d.WorkerPool)
	worker.id = i
	workers[i] = worker
	worker.Start()
    }

    go d.dispatch()
}

func (d *ReqDispatcher) dispatch() {
    for {
	select {
	    case req := <-RpcReqQueue:
	    // a job request has been received
	    go func(req RpcReq) {
		// try to obtain a worker job channel that is available.
		// this will block until a worker is idle
		reqChannel := <-d.WorkerPool

		// dispatch the job to the worker job channel
		reqChannel <- req
	    }(req)
	}
    }
}

func FindWorker(sid string) (*RpcReqWorker,error) {
    for i := 0; i < RpcMaxWorker; i++ {
	w := workers[i]

	if strings.EqualFold(w.sid,sid) {
	    return w,nil
	}
    }

    time.Sleep(time.Duration(5)*time.Second) //1000 == 1s //TODO
    
    for i := 0; i < RpcMaxWorker; i++ {
	w := workers[i]
	if strings.EqualFold(w.sid,sid) {
	    return w,nil
	}
    }

    return nil,fmt.Errorf("no find worker.")
}

func NewRpcReqWorker(workerPool chan chan RpcReq) *RpcReqWorker {
    return &RpcReqWorker{
    RpcReqWorkerPool: workerPool,
    RpcReqChannel: make(chan RpcReq),
    rpcquit:       make(chan bool),
    retres:list.New(),
    ch:		   make(chan interface{}),
    msg_share1:list.New(),
    splitmsg_share1:make(map[string]*list.List),
    msg_zkfact:list.New(),
    splitmsg_zkfact:make(map[string]*list.List),
    msg_zku:list.New(),
    splitmsg_zku:make(map[string]*list.List),
    msg_mtazk1proof:list.New(),
    splitmsg_mtazk1proof:make(map[string]*list.List),
    msg_c1:list.New(),
    splitmsg_c1:make(map[string]*list.List),
    msg_d1_1:list.New(),
    splitmsg_d1_1:make(map[string]*list.List),
    msg_c11:list.New(),
    splitmsg_c11:make(map[string]*list.List),
    msg_kc:list.New(),
    splitmsg_kc:make(map[string]*list.List),
    msg_mkg:list.New(),
    splitmsg_mkg:make(map[string]*list.List),
    msg_mkw:list.New(),
    splitmsg_mkw:make(map[string]*list.List),
    msg_delta1:list.New(),
    splitmsg_delta1:make(map[string]*list.List),
    msg_d11_1:list.New(),
    splitmsg_d11_1:make(map[string]*list.List),
    msg_s1:list.New(),
    splitmsg_s1:make(map[string]*list.List),
    msg_ss1:list.New(),
    splitmsg_ss1:make(map[string]*list.List),
    
    pkx:list.New(),
    pky:list.New(),
    save:list.New(),
    
    bc1:make(chan bool,1),
    bd1_1:make(chan bool,1),
    bc11:make(chan bool,1),
    bkc:make(chan bool,1),
    bs1:make(chan bool,1),
    bss1:make(chan bool,1),
    bmkg:make(chan bool,1),
    bmkw:make(chan bool,1),
    bshare1:make(chan bool,1),
    bzkfact:make(chan bool,1),
    bzku:make(chan bool,1),
    bmtazk1proof:make(chan bool,1),
    bdelta1:make(chan bool,1),
    bd11_1:make(chan bool,1),

    //ed
    bedc11:make(chan bool,1),
    msg_edc11:list.New(),
    bedzk:make(chan bool,1),
    msg_edzk:list.New(),
    bedd11:make(chan bool,1),
    msg_edd11:list.New(),
    bedshare1:make(chan bool,1),
    msg_edshare1:list.New(),
    bedcfsb:make(chan bool,1),
    msg_edcfsb:list.New(),
    edsave:list.New(),
    edpk:list.New(),
    bedc21:make(chan bool,1),
    msg_edc21:list.New(),
    bedzkr:make(chan bool,1),
    msg_edzkr:list.New(),
    bedd21:make(chan bool,1),
    msg_edd21:list.New(),
    bedc31:make(chan bool,1),
    msg_edc31:list.New(),
    bedd31:make(chan bool,1),
    msg_edd31:list.New(),
    beds:make(chan bool,1),
    msg_eds:list.New(),

    sid:"",
    }
}

func (w *RpcReqWorker) Clear() {

    w.sid = ""
    w.groupid = ""
    
    var next *list.Element
    
    for e := w.msg_c1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_c1.Remove(e)
    }
    
    for e := w.msg_kc.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_kc.Remove(e)
    }

    for e := w.msg_mkg.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_mkg.Remove(e)
    }

    for e := w.msg_mkw.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_mkw.Remove(e)
    }

    for e := w.msg_delta1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_delta1.Remove(e)
    }

    for e := w.msg_d1_1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_d1_1.Remove(e)
    }

    for e := w.msg_share1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_share1.Remove(e)
    }

    for e := w.msg_zkfact.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_zkfact.Remove(e)
    }

    for e := w.msg_zku.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_zku.Remove(e)
    }

    for e := w.msg_mtazk1proof.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_mtazk1proof.Remove(e)
    }

    for e := w.msg_c11.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_c11.Remove(e)
    }

    for e := w.msg_d11_1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_d11_1.Remove(e)
    }

    for e := w.msg_s1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_s1.Remove(e)
    }

    for e := w.msg_ss1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_ss1.Remove(e)
    }

    for e := w.pkx.Front(); e != nil; e = next {
        next = e.Next()
        w.pkx.Remove(e)
    }

    for e := w.pky.Front(); e != nil; e = next {
        next = e.Next()
        w.pky.Remove(e)
    }

    for e := w.save.Front(); e != nil; e = next {
        next = e.Next()
        w.save.Remove(e)
    }

    for e := w.retres.Front(); e != nil; e = next {
        next = e.Next()
        w.retres.Remove(e)
    }

    if len(w.ch) == 1 {
	<-w.ch
    }
    if len(w.rpcquit) == 1 {
	<-w.rpcquit
    }
    if len(w.bshare1) == 1 {
	<-w.bshare1
    }
    if len(w.bzkfact) == 1 {
	<-w.bzkfact
    }
    if len(w.bzku) == 1 {
	<-w.bzku
    }
    if len(w.bmtazk1proof) == 1 {
	<-w.bmtazk1proof
    }
    if len(w.bc1) == 1 {
	<-w.bc1
    }
    if len(w.bd1_1) == 1 {
	<-w.bd1_1
    }
    if len(w.bc11) == 1 {
	<-w.bc11
    }
    if len(w.bkc) == 1 {
	<-w.bkc
    }
    if len(w.bs1) == 1 {
	<-w.bs1
    }
    if len(w.bss1) == 1 {
	<-w.bss1
    }
    if len(w.bmkg) == 1 {
	<-w.bmkg
    }
    if len(w.bmkw) == 1 {
	<-w.bmkw
    }
    if len(w.bdelta1) == 1 {
	<-w.bdelta1
    }
    if len(w.bd11_1) == 1 {
	<-w.bd11_1
    }

    //ed
    if len(w.bedc11) == 1 {
	<-w.bedc11
    }
    for e := w.msg_edc11.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edc11.Remove(e)
    }

    if len(w.bedzk) == 1 {
	<-w.bedzk
    }
    for e := w.msg_edzk.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edzk.Remove(e)
    }
    if len(w.bedd11) == 1 {
	<-w.bedd11
    }
    for e := w.msg_edd11.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edd11.Remove(e)
    }
    if len(w.bedshare1) == 1 {
	<-w.bedshare1
    }
    for e := w.msg_edshare1.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edshare1.Remove(e)
    }
    if len(w.bedcfsb) == 1 {
	<-w.bedcfsb
    }
    for e := w.msg_edcfsb.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edcfsb.Remove(e)
    }
    for e := w.edsave.Front(); e != nil; e = next {
        next = e.Next()
        w.edsave.Remove(e)
    }
    for e := w.edpk.Front(); e != nil; e = next {
        next = e.Next()
        w.edpk.Remove(e)
    }
    
    if len(w.bedc21) == 1 {
	<-w.bedc21
    }
    for e := w.msg_edc21.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edc21.Remove(e)
    }
    if len(w.bedzkr) == 1 {
	<-w.bedzkr
    }
    for e := w.msg_edzkr.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edzkr.Remove(e)
    }
    if len(w.bedd21) == 1 {
	<-w.bedd21
    }
    for e := w.msg_edd21.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edd21.Remove(e)
    }
    if len(w.bedc31) == 1 {
	<-w.bedc31
    }
    for e := w.msg_edc31.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edc31.Remove(e)
    }
    if len(w.bedd31) == 1 {
	<-w.bedd31
    }
    for e := w.msg_edd31.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_edd31.Remove(e)
    }
    if len(w.beds) == 1 {
	<-w.beds
    }
    for e := w.msg_eds.Front(); e != nil; e = next {
        next = e.Next()
        w.msg_eds.Remove(e)
    }

    //TODO
    w.splitmsg_c1 = make(map[string]*list.List)
    w.splitmsg_kc = make(map[string]*list.List)
    w.splitmsg_mkg = make(map[string]*list.List)
    w.splitmsg_mkw = make(map[string]*list.List)
    w.splitmsg_delta1 = make(map[string]*list.List)
    w.splitmsg_d1_1 = make(map[string]*list.List)
    w.splitmsg_share1 = make(map[string]*list.List)
    w.splitmsg_zkfact = make(map[string]*list.List)
    w.splitmsg_zku = make(map[string]*list.List)
    w.splitmsg_mtazk1proof = make(map[string]*list.List)
    w.splitmsg_c11 = make(map[string]*list.List)
    w.splitmsg_d11_1 = make(map[string]*list.List)
    w.splitmsg_s1 = make(map[string]*list.List)
    w.splitmsg_ss1 = make(map[string]*list.List)
}

func (w *RpcReqWorker) Start() {
    go func() {

	for {
	    // register the current worker into the worker queue.
	    w.RpcReqWorkerPool <- w.RpcReqChannel
	    select {
		    case req := <-w.RpcReqChannel:
			    req.rpcdata.Run(w.id,req.ch)
			    w.Clear()

		    case <-w.rpcquit:
			// we have received a signal to stop
			    return
		}
	}
    }()
}

func (w *RpcReqWorker) Stop() {
    go func() {
	w.rpcquit <- true
    }()
}
//rpc-req

type WorkReq interface {
    Run(workid int,ch chan interface{}) bool
}

//RecvMsg
type RecvMsg struct {
    msg string
    groupid string
}

func Dcrmcall(msg interface{},enode string) <-chan string {
    ch := make(chan string, 1)
    GroupId := GetGroupIdByEnode(enode)
    fmt.Println("=========Dcrmcall===========","GroupId",GroupId,"enode",enode)
    //if !strings.EqualFold(GroupId,enode) {
    if strings.EqualFold(GroupId,"") {
	ret := ("fail"+Sep+"xxx"+Sep+"error group id")
	ch <- ret 
	return ch
    }
    
    s := msg.(string)
    v := RecvMsg{msg:s,groupid:GroupId}
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:&v,ch:rch}
    RpcReqQueue <- req
    chret,cherr := GetChannelValue(sendtogroup_timeout,rch)
    if cherr != nil {
	//fail:chret:error
	ret := ("fail"+Sep+chret+Sep+cherr.Error())
	ch <- ret 
	return ch
    }

    //success:chret
    ret := ("success"+Sep+chret)
    ch <- ret 
    return ch
}

func Dcrmcallret(msg interface{},enode string) {
    res := msg.(string)
    if res == "" {
	return
    }
   
    fmt.Println("=========Dcrmcallret,node count=%v==============",NodeCnt)

    ss := strings.Split(res,Sep)
    if len(ss) != 4 {
	return
    }

    status := ss[0]
    //msgtype := ss[2]
    ret := ss[3]
    workid,err := strconv.Atoi(ss[1])
    if err != nil || workid < 0 {
	return
    }

    //success:workid:msgtype:ret
    if status == "success" {
	w := workers[workid]
	res2 := RpcDcrmRes{Ret:ss[3],Err:nil}
	w.retres.PushBack(&res2)

	if ss[2] == "rpc_sign" {
	    if w.retres.Len() == NodeCnt {
		ret := GetGroupRes(workid)
		w.ch <- ret
	    }
	}
	    
	if ss[2] == "rpc_req_dcrmaddr" {
	    if w.retres.Len() == NodeCnt {
		ret := GetGroupRes(workid)
		w.ch <- ret
	    }
	}

	return
    }
    
    //fail:workid:msgtype:error
    if status == "fail" {
	w := workers[workid]
	var ret2 Err
	ret2.Info = ret
	res2 := RpcDcrmRes{Ret:"",Err:ret2}
	w.retres.PushBack(&res2)

	if ss[2] == "rpc_sign" {
	    if w.retres.Len() == NodeCnt {
		ret := GetGroupRes(workid)
		w.ch <- ret
	    }
	}

	if ss[2] == "rpc_req_dcrmaddr" {
	    if w.retres.Len() == NodeCnt {
		ret := GetGroupRes(workid)
		w.ch <- ret
	    }
	}
	
	return
    }
}

func GetGroupRes(wid int) RpcDcrmRes {
    if wid < 0 {
	res2 := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	return res2
    }

    var l *list.List
    w := workers[wid]
    l = w.retres

    if l == nil {
	res2 := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetNoResFromGroupMem)}
	return res2
    }

    var err error
    iter := l.Front()
    for iter != nil {
	ll := iter.Value.(*RpcDcrmRes)
	err = ll.Err
	if err == nil {
	    return (*ll)
	}
	iter = iter.Next()
    }

    iter = l.Front()
    for iter != nil {
	ll := iter.Value.(*RpcDcrmRes)
	err = ll.Err
	res2 := RpcDcrmRes{Ret:"",Err:err}
	return res2
	
	iter = iter.Next()
    }
    
    res2 := RpcDcrmRes{Ret:"",Err:nil}
    return res2
}

//=========================================

func Call(msg interface{},enode string) {
    s := msg.(string)
    SetUpMsgList(s)
}

func SetUpMsgList(msg string) {

    v := RecvMsg{msg:msg}
    //rpc-req
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:&v,ch:rch}
    RpcReqQueue <- req
}

func (self *RecvMsg) Run(workid int,ch chan interface{}) bool {
    if workid < 0 { //TODO
	res2 := RpcDcrmRes{Ret:"",Err:fmt.Errorf("no find worker.")}
	ch <- res2
	return false
    }

    /////////
    res := self.msg
    if res == "" { //TODO
	return false 
    }

    mm := strings.Split(res,Sep)
    if len(mm) >= 2 {
	//msg:  hash-enode:C1:X1:X2
	DisMsg(res)
	return true 
    }
    
    res,err := UnCompress(res)
    if err != nil {
	return false
    }
    r,err := Decode2(res)
    if err != nil {
	return false
    }

    switch r.(type) {
    case *SendMsg:
	rr := r.(*SendMsg)

	if rr.MsgType == "ec2_data" {
	    mm := strings.Split(rr.Msg,Sep)
	    if len(mm) >= 2 {
		//msg:  hash-enode:C1:X1:X2
		DisMsg(rr.Msg)
		return true 
	    }
	    return true
	}

	//rpc_sign
	if rr.MsgType == "rpc_sign" {
	    w := workers[workid]
	    w.sid = rr.Nonce
	    w.groupid = self.groupid
	    //msg = pubkey:keytype:message 
	    msg := rr.Msg
	    msgs := strings.Split(msg,":")

	    rch := make(chan interface{},1)
	    validate_lockout(w.sid,msgs[0],msgs[1],msgs[2],rch)
	    chret,cherr := GetChannelValue(ch_t,rch)
	    if chret != "" {
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType+Sep+chret,Err:nil}
		ch <- res2
		return true
	    }

	    if cherr != nil {
		var ret2 Err
		ret2.Info = cherr.Error() 
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Err:ret2}
		ch <- res2
		return false
	    }
	    
	    res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Err:fmt.Errorf("send tx to net fail.")}
	    ch <- res2
	    return true
	}
	//rpc_req_dcrmaddr
	if rr.MsgType == "rpc_req_dcrmaddr" {
	    //msg = keytype 
	    rch := make(chan interface{},1)
	    w := workers[workid]
	    w.sid = rr.Nonce
	    w.groupid = self.groupid

	    dcrm_liloreqAddress(w.sid,rr.Msg,rch)
	    chret,cherr := GetChannelValue(ch_t,rch)
	    if cherr != nil {
		var ret2 Err
		ret2.Info = cherr.Error()
		res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType,Err:ret2}
		ch <- res2
		return false
	    }
	    
	    res2 := RpcDcrmRes{Ret:strconv.Itoa(rr.WorkId)+Sep+rr.MsgType+Sep+chret,Err:nil}
	    ch <- res2
	    return true
	}

    default:
	return false
    }
    /////////

    return true 
}
type SendMsg struct {
    MsgType string
    Nonce string 
    WorkId int
    Msg string
}
func Encode2(obj interface{}) (string,error) {
    switch obj.(type) {
    case *SendMsg:
	ch := obj.(*SendMsg)
	ret,err := json.Marshal(ch)
	if err != nil {
	    return "",err
	}
	return string(ret),nil
    default:
	return "",fmt.Errorf("encode obj fail.")
    }
}

func Decode2(s string) (interface{},error) {
    var m SendMsg
    err := json.Unmarshal([]byte(s), &m)
    if err != nil {
	return nil,err
    }

    return &m,nil
} 
///////

////compress
func Compress(c []byte) (string,error) {
    if c == nil {
	return "",fmt.Errorf("compress fail.")
    }

    var in bytes.Buffer
    w,err := zlib.NewWriterLevel(&in,zlib.BestCompression-1)
    if err != nil {
	return "",err
    }

    w.Write(c)
    w.Close()

    s := in.String()
    return s,nil
}

////uncompress
func UnCompress(s string) (string,error) {

    if s == "" {
	return "",fmt.Errorf("param error.")
    }

    var data bytes.Buffer
    data.Write([]byte(s))

    r,err := zlib.NewReader(&data)
    if err != nil {
	return "",err
    }

    var out bytes.Buffer
    io.Copy(&out, r)
    return out.String(),nil
}
////

type DcrmHash [32]byte
func (h DcrmHash) Hex() string { return hexutil.Encode(h[:]) }

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h DcrmHash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}

type ReqAddrSendMsgToDcrm struct {
    KeyType string
}

func (self *ReqAddrSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    GetEnodesInfo()
    timestamp := time.Now().Unix()
    tt := strconv.Itoa(int(timestamp))
    nonce := Keccak256Hash([]byte(self.KeyType + ":" + tt + ":" + strconv.Itoa(workid))).Hex()
    
    sm := &SendMsg{MsgType:"rpc_req_dcrmaddr",Nonce:nonce,WorkId:workid,Msg:self.KeyType}
    res,err := Encode2(sm)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return false
    }

    res,err = Compress([]byte(res))
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return false
    }

    GroupId := GetGroupIdByEnode(cur_enode)
    fmt.Println("=========ReqAddrSendMsgToMsg.Run===========","GroupId",GroupId,"cur_enode",cur_enode)
    //if !strings.EqualFold(GroupId,cur_enode) {
    if strings.EqualFold(GroupId,"") {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return false
    }

    s := SendToGroupAllNodes(GroupId,res)
    
    if strings.EqualFold(s,"send fail.") {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrSendDataToGroupFail)}
	ch <- res
	return false
    }

    fmt.Println("=========ReqAddrSendMsgToMsg.Run,waiting for result===========","GroupId",GroupId,"cur_enode",cur_enode)
    w := workers[workid]
    chret,cherr := GetChannelValue(sendtogroup_timeout,w.ch)
    if cherr != nil {
	res2 := RpcDcrmRes{Ret:chret,Err:cherr}
	ch <- res2
	return false
    }
    res2 := RpcDcrmRes{Ret:chret,Err:cherr}
    ch <- res2

    return true
}

type SignSendMsgToDcrm struct {
    PubKey string
    KeyType string
    Message string
}

func (self *SignSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    /////check message
    message := self.Message
    txhashs := []rune(message)
    if string(txhashs[0:2]) != "0x" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("message must be 16-in-32-byte character sprang at the beginning of 0x,for example: 0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41")}
	ch <- res
	return false
    }
    message = string(txhashs[2:])
    if len(message) != 64 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("message must be 16-in-32-byte character sprang at the beginning of 0x,for example: 0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41")}
	ch <- res
	return false
    }
    //////

    GetEnodesInfo()
    msg := self.PubKey + ":" + self.KeyType + ":" + self.Message
    timestamp := time.Now().Unix()
    tt := strconv.Itoa(int(timestamp))
    nonce := Keccak256Hash([]byte(msg + ":" + tt + ":" + strconv.Itoa(workid))).Hex()
    
    sm := &SendMsg{MsgType:"rpc_sign",Nonce:nonce,WorkId:workid,Msg:msg}
    res,err := Encode2(sm)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return false
    }

    res,err = Compress([]byte(res))
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return false
    }

    GroupId := GetGroupIdByEnode(cur_enode)
    fmt.Println("=========SignSendMsgToDcrm.Run===========","GroupId",GroupId,"cur_enode",cur_enode)
    if strings.EqualFold(GroupId,"") {
    //if !strings.EqualFold(GroupId,cur_enode) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return false
    }
    s := SendToGroupAllNodes(GroupId,res)
    if strings.EqualFold(s,"send fail.") {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrSendDataToGroupFail)}
	ch <- res
	return false
    }

    fmt.Println("=========SignSendMsgToDcrm.Run,waiting for result.===========","GroupId",GroupId,"cur_enode",cur_enode)
    w := workers[workid]
    chret,cherr := GetChannelValue(sendtogroup_lilo_timeout,w.ch)
    if cherr != nil {
	res2 := RpcDcrmRes{Ret:chret,Err:cherr}
	ch <- res2
	return false
    }
    res2 := RpcDcrmRes{Ret:chret,Err:cherr}
    ch <- res2

    return true
}

//ec2
//msgprex = hash 
func dcrm_liloreqAddress(msgprex string,keytype string,ch chan interface{}) {

    fmt.Println("========dcrm_liloreqAddress============")
    GetEnodesInfo()

    if int32(Enode_cnts) != int32(NodeCnt) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return
    }

    wk,err := FindWorker(msgprex)
    if err != nil || wk == nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return
    }
    id := wk.id

    ok := KeyGenerate_ec2(msgprex,ch,id,keytype)
    if ok == false {
	return
    }

    iter := workers[id].pkx.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenPubkeyFail)}
	ch <- res
	return
    }
    spkx := iter.Value.(string)
    pkx := new(big.Int).SetBytes([]byte(spkx))
    iter = workers[id].pky.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenPubkeyFail)}
	ch <- res
	return
    }
    spky := iter.Value.(string)
    pky := new(big.Int).SetBytes([]byte(spky))
    ys := secp256k1.S256().Marshal(pkx,pky)

    iter = workers[id].save.Front()
    if iter == nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetGenSaveDataFail)}
	ch <- res
	return
    }
    save := iter.Value.(string)

    lock.Lock()
    //write db
    dir := GetDbDir()
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrCreateDbFail)}
	ch <- res
	lock.Unlock()
	return
    }

    pubkeyhex := hex.EncodeToString(ys)

    s := []string{string(ys),save} ////fusionaddr ??
    ss := strings.Join(s,Sep)
    db.Put(ys,[]byte(ss),nil)
    db.Close()
    lock.Unlock()
    res := RpcDcrmRes{Ret:pubkeyhex,Err:nil}
    ch <- res
}

//ec2
//msgprex = hash 
func KeyGenerate_ec2(msgprex string,ch chan interface{},id int,cointype string) bool {
    if id < 0 || id >= RpcMaxWorker || id >= len(workers) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetWorkerIdError)}
	ch <- res
	return false
    }

    w := workers[id]
    GroupId := w.groupid 
    fmt.Println("========KeyGenerate_ec2============","GroupId",GroupId)
    if GroupId == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return false
    }
    
    ns,_ := GetGroup(GroupId)
    if ns != NodeCnt {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGroupNotReady)}
	ch <- res
	return false 
    }

    //1. generate their own "partial" private key secretly
    u1 := GetRandomIntFromZn(secp256k1.S256().N)

    // 2. calculate "partial" public key, make "pritial" public key commiment to get (C,D)
    u1Gx, u1Gy := secp256k1.S256().ScalarBaseMult(u1.Bytes())
    commitU1G := new(lib.Commitment).Commit(u1Gx, u1Gy)

    // 3. generate their own paillier public key and private key
    u1PaillierPk, u1PaillierSk := lib.GenerateKeyPair(PaillierKeyLength)

    // 4. Broadcast
    // commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
    // u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C1"
    s1 := string(commitU1G.C.Bytes())
    s2 := u1PaillierPk.Length
    s3 := string(u1PaillierPk.N.Bytes()) 
    s4 := string(u1PaillierPk.G.Bytes()) 
    s5 := string(u1PaillierPk.N2.Bytes()) 
    ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
    // u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
     _,cherr := GetChannelValue(ch_t,w.bc1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetC1Timeout)}
	ch <- res
	return false 
    }

    // 2. generate their vss to get shares which is a set
    // [notes]
    // all nodes has their own id, in practival, we can take it as double hash of public key of fusion

    ids := GetIds(cointype,GroupId)

    u1PolyG, _, u1Shares, err := lib.Vss(u1, ids, ThresHold, NodeCnt)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:err}
	ch <- res
	return false 
    }

    // 3. send the the proper share to proper node 
    //example for u1:
    // Send u1Shares[0] to u1
    // Send u1Shares[1] to u2
    // Send u1Shares[2] to u3
    // Send u1Shares[3] to u4
    // Send u1Shares[4] to u5
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)

	if enodes == "" {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetEnodeByUIdFail)}
	    ch <- res
	    return false
	}
	
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	for _,v := range u1Shares {
	    uid := lib.GetSharesId(v)
	    if uid.Cmp(id) == 0 {
		mp := []string{msgprex,cur_enode}
		enode := strings.Join(mp,"-")
		s0 := "SHARE1"
		s1 := strconv.Itoa(v.T) 
		s2 := string(v.Id.Bytes()) 
		s3 := string(v.Share.Bytes()) 
		ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3
		SendMsgToPeer(enodes,ss)
		break
	    }
	}
    }

    // 4. Broadcast
    // commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
    // u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "D1"
    dlen := len(commitU1G.D)
    s1 = strconv.Itoa(dlen)

    ss = enode + Sep + s0 + Sep + s1 + Sep
    for _,d := range commitU1G.D {
	ss += string(d.Bytes())
	ss += Sep
    }

    s2 = strconv.Itoa(u1PolyG.T)
    s3 = strconv.Itoa(u1PolyG.N)
    ss = ss + s2 + Sep + s3 + Sep

    pglen := 2*(len(u1PolyG.PolyG))
    s4 = strconv.Itoa(pglen)

    ss = ss + s4 + Sep

    for _,p := range u1PolyG.PolyG {
	for _,d := range p {
	    ss += string(d.Bytes())
	    ss += Sep
	}
    }
    ss = ss + "NULL"
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
    // u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
    _,cherr = GetChannelValue(ch_t,w.bd1_1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetD1Timeout)}
	ch <- res
	return false 
    }

    // 2. Receive Personal Data
    _,cherr = GetChannelValue(ch_t,w.bshare1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetSHARE1Timeout)}
	ch <- res
	return false 
    }
	 
    shares := make([]string,NodeCnt-1)
    if w.msg_share1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllSHARE1Fail)}
	ch <- res
	return false
    }
    itmp := 0
    iter := w.msg_share1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	shares[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }
    
    //var sstruct = make(map[string]*vss.ShareStruct)
    var sstruct = make(map[string]*lib.ShareStruct)
    for _,v := range shares {
	mm := strings.Split(v, Sep)
	t,_ := strconv.Atoi(mm[2])
	ushare := &lib.ShareStruct{T:t,Id:new(big.Int).SetBytes([]byte(mm[3])),Share:new(big.Int).SetBytes([]byte(mm[4]))}
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	sstruct[prexs[len(prexs)-1]] = ushare
    }
    for _,v := range u1Shares {
	uid := lib.GetSharesId(v)
	enodes := GetEnodesByUid(uid,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    sstruct[cur_enode] = v 
	    break
	}
    }

    ds := make([]string,NodeCnt-1)
    if w.msg_d1_1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllD1Fail)}
	ch <- res
	return false
    }
    itmp = 0
    iter = w.msg_d1_1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	ds[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    var upg = make(map[string]*lib.PolyGStruct)
    for _,v := range ds {
	mm := strings.Split(v, Sep)
	dlen,_ := strconv.Atoi(mm[2])
	pglen,_ := strconv.Atoi(mm[3+dlen+2])
	pglen = (pglen/2)
	var pgss = make([][]*big.Int, 0)
	l := 0
	for j:=0;j<pglen;j++ {
	    l++
	    var gg = make([]*big.Int,0)
	    gg = append(gg,new(big.Int).SetBytes([]byte(mm[5+dlen+l])))
	    l++
	    gg = append(gg,new(big.Int).SetBytes([]byte(mm[5+dlen+l])))
	    pgss = append(pgss,gg)
	}

	t,_ := strconv.Atoi(mm[3+dlen])
	n,_ := strconv.Atoi(mm[4+dlen])
	ps := &lib.PolyGStruct{T:t,N:n,PolyG:pgss}
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	upg[prexs[len(prexs)-1]] = ps
    }
    upg[cur_enode] = u1PolyG

    // 3. verify the share
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if sstruct[en[0]].Verify(upg[en[0]]) == false {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifySHARE1Fail)}
	    ch <- res
	    return false
	}
    }

    // 4.verify and de-commitment to get uG
    // for all nodes, construct the commitment by the receiving C and D
    cs := make([]string,NodeCnt-1)
    if w.msg_c1.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllC1Fail)}
	ch <- res
	return false
    }
    itmp = 0
    iter = w.msg_c1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	cs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    var udecom = make(map[string]*lib.Commitment)
    for _,v := range cs {
	mm := strings.Split(v, Sep)
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range ds {
	    mmm := strings.Split(vv, Sep)
	    prex2 := mmm[0]
	    prexs2 := strings.Split(prex2,"-")
	    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
		dlen,_ := strconv.Atoi(mmm[2])
		var gg = make([]*big.Int,0)
		l := 0
		for j:=0;j<dlen;j++ {
		    l++
		    gg = append(gg,new(big.Int).SetBytes([]byte(mmm[2+l])))
		}
		deCommit := &lib.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		udecom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }
    deCommit_commitU1G := &lib.Commitment{C: commitU1G.C, D: commitU1G.D}
    udecom[cur_enode] = deCommit_commitU1G

    // for all nodes, verify the commitment
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if udecom[en[0]].Verify() == false {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrKeyGenVerifyCommitFail)}
	    ch <- res
	    return false
	}
    }

    // for all nodes, de-commitment
    var ug = make(map[string][]*big.Int)
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	_, u1G := udecom[en[0]].DeCommit()
	ug[en[0]] = u1G
    }

    // for all nodes, calculate the public key
    var pkx *big.Int
    var pky *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	pkx = (ug[en[0]])[0]
	pky = (ug[en[0]])[1]
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	pkx, pky = secp256k1.S256().Add(pkx, pky, (ug[en[0]])[0],(ug[en[0]])[1])
    }
    w.pkx.PushBack(string(pkx.Bytes()))
    w.pky.PushBack(string(pky.Bytes()))

    // 5. calculate the share of private key
    var skU1 *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	skU1 = sstruct[en[0]].Share
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	skU1 = new(big.Int).Add(skU1,sstruct[en[0]].Share)
    }
    skU1 = new(big.Int).Mod(skU1, secp256k1.S256().N)

    //save skU1/u1PaillierSk/u1PaillierPk/...
    ss = string(skU1.Bytes())
    ss = ss + SepSave
    s1 = u1PaillierSk.Length
    s2 = string(u1PaillierSk.L.Bytes()) 
    s3 = string(u1PaillierSk.U.Bytes())
    ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    s1 = u1PaillierPk.Length
	    s2 = string(u1PaillierPk.N.Bytes()) 
	    s3 = string(u1PaillierPk.G.Bytes()) 
	    s4 = string(u1PaillierPk.N2.Bytes()) 
	    ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave + s4 + SepSave
	    continue
	}
	for _,v := range cs {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		s1 = mm[3] 
		s2 = mm[4] 
		s3 = mm[5] 
		s4 = mm[6] 
		ss = ss + s1 + SepSave + s2 + SepSave + s3 + SepSave + s4 + SepSave
		break
	    }
	}
    }

    sstmp := ss //////
    tmp := ss

    ss = ss + "NULL"

    // 6. calculate the zk
    // ## add content: zk of paillier key, zk of u
    
    // zk of paillier key
    u1zkFactProof := u1PaillierSk.ZkFactProve()
    // zk of u
    //u1zkUProof := schnorrZK.ZkUProve(u1)
    u1zkUProof := lib.ZkUProve(u1)

    // 7. Broadcast zk
    // u1zkFactProof, u2zkFactProof, u3zkFactProof, u4zkFactProof, u5zkFactProof
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "ZKFACTPROOF"
    s1 = string(u1zkFactProof.H1.Bytes())
    s2 = string(u1zkFactProof.H2.Bytes())
    s3 = string(u1zkFactProof.Y.Bytes())
    s4 = string(u1zkFactProof.E.Bytes())
    s5 = string(u1zkFactProof.N.Bytes())
    ss = enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast zk
    // u1zkFactProof, u2zkFactProof, u3zkFactProof, u4zkFactProof, u5zkFactProof
    _,cherr = GetChannelValue(ch_t,w.bzkfact)
    if cherr != nil {
//	log.Debug("get w.bzkfact timeout in keygenerate.")
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetZKFACTPROOFTimeout)}
	ch <- res
	return false 
    }

    sstmp2 := s1 + SepSave + s2 + SepSave + s3 + SepSave + s4 + SepSave + s5

    // 8. Broadcast zk
    // u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "ZKUPROOF"
    s1 = string(u1zkUProof.E.Bytes())
    s2 = string(u1zkUProof.S.Bytes())
    ss = enode + Sep + s0 + Sep + s1 + Sep + s2
    SendMsgToDcrmGroup(ss,GroupId)

    // 9. Receive Broadcast zk
    // u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
    _,cherr = GetChannelValue(ch_t,w.bzku)
    if cherr != nil {
//	log.Info("get w.bzku timeout in keygenerate.")
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetZKUPROOFTimeout)}
	ch <- res
	return false 
    }
    
    // 1. verify the zk
    // ## add content: verify zk of paillier key, zk of u
	
    // for all nodes, verify zk of paillier key
    zkfacts := make([]string,NodeCnt-1)
    if w.msg_zkfact.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllZKFACTPROOFFail)}
	ch <- res
	return false
    }
    itmp = 0
    iter = w.msg_zkfact.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	zkfacts[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for k,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) { /////bug for save zkfact
	    sstmp = sstmp + sstmp2 + SepSave
	    continue
	}

	u1PaillierPk2 := GetPaillierPk(tmp,k)
	for _,v := range zkfacts {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		h1 := new(big.Int).SetBytes([]byte(mm[2]))
		h2 := new(big.Int).SetBytes([]byte(mm[3]))
		y := new(big.Int).SetBytes([]byte(mm[4]))
		e := new(big.Int).SetBytes([]byte(mm[5]))
		n := new(big.Int).SetBytes([]byte(mm[6]))
		zkFactProof := &lib.ZkFactProof{H1: h1, H2: h2, Y: y, E: e,N:n}
		///////
		sstmp = sstmp + mm[2] + SepSave + mm[3] + SepSave + mm[4] + SepSave + mm[5] + SepSave + mm[6] + SepSave  ///for save zkfact
		//////

		if !u1PaillierPk2.ZkFactVerify(zkFactProof) {
		    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyZKFACTPROOFFail)}
		    ch <- res
	    
		    return false 
		}

		break
	    }
	}
    }

    // for all nodes, verify zk of u
    zku := make([]string,NodeCnt-1)
    if w.msg_zku.Len() != (NodeCnt-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllZKUPROOFFail)}
	ch <- res
	return false
    }
    itmp = 0
    iter = w.msg_zku.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	zku[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range ids {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	for _,v := range zku {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		e := new(big.Int).SetBytes([]byte(mm[2]))
		s := new(big.Int).SetBytes([]byte(mm[3]))
		zkUProof := &lib.ZkUProof{E: e, S: s}
		if !lib.ZkUVerify(ug[en[0]],zkUProof) {
		    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyZKUPROOFFail)}
		    ch <- res
		    return false 
		}

		break
	    }
	}
    } 
    
    sstmp = sstmp + "NULL"
    //w.save <- sstmp
    //w.save:  sku1:UiSK:U1PK:U2PK:U3PK:....:UnPK:U1H1:U1H2:U1Y:U1E:U1N:U2H1:U2H2:U2Y:U2E:U2N:U3H1:U3H2:U3Y:U3E:U3N:......:NULL
    w.save.PushBack(sstmp)
    return true
}

func validate_lockout(wsid string,pubkey string,keytype string,message string,ch chan interface{}) {
    fmt.Println("========validate_lockout============")
    lock5.Lock()
    pub, err := hex.DecodeString(pubkey)
    if err != nil {
        res := RpcDcrmRes{Ret:"",Err:err}
        ch <- res
        lock5.Unlock()
        return
    }

    //db
    dir := GetDbDir()
    ////////
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
        fmt.Println("===========validate_lockout,open db fail.=============")
        res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("open db fail.")}
        ch <- res
        lock5.Unlock()
        return
    } 

    var data string
    var b bytes.Buffer 
    b.WriteString("") 
    b.WriteByte(0) 
    b.WriteString("") 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	key := string(iter.Key())
	value := string(iter.Value())
	if strings.EqualFold(key,string(pub)) {
	    data = value
	    break
	}
    }
    iter.Release()
    ///////
    if data == "" {
	fmt.Println("===========get generate save data fail.=============")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get data fail.")}
	ch <- res
	db.Close()
	lock5.Unlock()
	return
    }
    
    datas := strings.Split(data,Sep)

    realdcrmpubkey := hex.EncodeToString([]byte(datas[0]))
    if !strings.EqualFold(realdcrmpubkey,pubkey) {
        res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get data fail")}
        ch <- res
        db.Close()
        lock5.Unlock()
        return
    }

    db.Close()
    lock5.Unlock()

    rch := make(chan interface{}, 1)
    dcrm_sign(wsid,"xxx",message,realdcrmpubkey,keytype,rch)
    ret,cherr := GetChannelValue(ch_t,rch)
    if cherr != nil {
	    res := RpcDcrmRes{Ret:"",Err:cherr}
	    ch <- res
	    return
    }

    res := RpcDcrmRes{Ret:ret,Err:nil}
    ch <- res
    return
}

func IsInGroup(enode string,groupId string) bool {
    if groupId == "" || enode == "" {
	return false
    }

    cnt,enodes := GetGroup(groupId)
    if cnt <= 0 || enodes == "" {
	return false
    }

    nodes := strings.Split(enodes,SepSg)
    for _,node := range nodes {
	node2 := ParseNode(node)
	if strings.EqualFold(node2,enode) {
	    return true
	}
    }

    return false
}

func GetGroupIdByEnode(enode string) string {
    if enode == "" {
	return ""
    }

    lock.Lock()
    dir := GetGroupDir()
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
	lock.Unlock()
	return "" 
    }

    var data string
    var b bytes.Buffer 
    b.WriteString("") 
    b.WriteByte(0) 
    b.WriteString("") 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	key := string(iter.Key())
	value := string(iter.Value())
	if strings.EqualFold(key,"GroupIds") {
	    data = value
	    break
	}
    }
    iter.Release()
    ///////
    if data == "" {
	db.Close()
	lock.Unlock()
	return "" 
    }

    m := strings.Split(data,":")
    for _,v := range m {
	if IsInGroup(enode,v) {
	    db.Close()
	    lock.Unlock()
	    return v 
	}
    }

    db.Close()
    lock.Unlock()
    return ""
}

func GetEnodesInfo() {
    GroupId := GetGroupIdByEnode(cur_enode)
    if GroupId == "" {
	return
    }
    Enode_cnts,_ = GetGroup(GroupId)
    NodeCnt = Enode_cnts
    cur_enode = GetSelfEnode()
}

func SendReqToGroup(msg string,rpctype string) (string,error) {
    var req RpcReq
    switch rpctype {
	case "rpc_req_dcrmaddr":
	    v := ReqAddrSendMsgToDcrm{KeyType:msg}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_sign":
	    m := strings.Split(msg,":")
	    v := SignSendMsgToDcrm{PubKey:m[0],KeyType:m[1],Message:m[2]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	default:
	    return "",nil
    }

    var t int
    if rpctype == "rpc_sign" {
	t = sendtogroup_lilo_timeout 
    } else {
	t = sendtogroup_timeout
    }

    RpcReqQueue <- req
    chret,cherr := GetChannelValue(t,req.ch)
    if cherr != nil {
	return chret,cherr
    }

    return chret,nil
}

func GetChannelValue(t int,obj interface{}) (string,error) {
    timeout := make(chan bool, 1)
    go func(timeout chan bool) {
	 time.Sleep(time.Duration(t)*time.Second) //1000 == 1s
	 timeout <- true
     }(timeout)

     switch obj.(type) {
	 case chan interface{} :
	     ch := obj.(chan interface{})
	     select {
		 case v := <- ch :
		     ret,ok := v.(RpcDcrmRes)
		     if ok == true {
			 return ret.Ret,ret.Err
		     }
		 case <- timeout :
		     return "",fmt.Errorf("get data from node fail.")
	     }
	 case chan string:
	     ch := obj.(chan string)
	     select {
		 case v := <- ch :
			    return v,nil 
		 case <- timeout :
		     return "",fmt.Errorf("get data from node fail.")
	     }
	 case chan int64:
	     ch := obj.(chan int64)
	     select {
		 case v := <- ch :
		    return strconv.Itoa(int(v)),nil 
		 case <- timeout :
		     return "",fmt.Errorf("get data from node fail.")
	     }
	 case chan int:
	     ch := obj.(chan int)
	     select {
		 case v := <- ch :
		    return strconv.Itoa(v),nil 
		 case <- timeout :
		     return "",fmt.Errorf("get data from node fail.")
	     }
	 case chan bool:
	     ch := obj.(chan bool)
	     select {
		 case v := <- ch :
		    if !v {
			return "false",nil
		    } else {
			return "true",nil
		    }
		 case <- timeout :
		     return "",fmt.Errorf("get data from node fail.")
	     }
	 default:
	    return "",fmt.Errorf("unknown ch type.") 
     }

     return "",fmt.Errorf("get value fail.")
 }

//error type 1
type Err struct {
	Info  string
}

func (e Err) Error() string {
	return e.Info
}

//msg:  hash-enode:C1:X1:X2
func DisMsg(msg string) {

    if msg == "" {
	return
    }

    //orderbook matchres
    mm := strings.Split(msg, Sep)
    if len(mm) < 3 {
	return
    }
    
    mms := mm[0]
    prexs := strings.Split(mms,"-")
    if len(prexs) < 2 {
	return
    }

	//msg:  hash-enode:C1:X1:X2
	w,err := FindWorker(prexs[0])
	if err != nil || w == nil {
	    return
	}

	msgCode := mm[1]
	switch msgCode {
	case "C1":
	    ///bug
	    if w.msg_c1.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_c1.PushBack(msg)
	    if w.msg_c1.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All C1===========","GroupId",w.groupid)
		w.bc1 <- true
	    }
	case "D1":
	    ///bug
	    if w.msg_d1_1.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_d1_1.PushBack(msg)
	    if w.msg_d1_1.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All D1===========","GroupId",w.groupid)
		w.bd1_1 <- true
	    }
	case "SHARE1":
	    ///bug
	    if w.msg_share1.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_share1.PushBack(msg)
	    if w.msg_share1.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All SHARE1===========","GroupId",w.groupid)
		w.bshare1 <- true
	    }
	case "ZKFACTPROOF":
	    ///bug
	    if w.msg_zkfact.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_zkfact.PushBack(msg)
	    if w.msg_zkfact.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All ZKFACTPROOF===========","GroupId",w.groupid)
		w.bzkfact <- true
	    }
	case "ZKUPROOF":
	    ///bug
	    if w.msg_zku.Len() >= (NodeCnt-1) {
		return
	    }
	    ///
	    w.msg_zku.PushBack(msg)
	    if w.msg_zku.Len() == (NodeCnt-1) {
		fmt.Println("=========Get All ZKUPROOF===========","GroupId",w.groupid)
		w.bzku <- true
	    }
	case "MTAZK1PROOF":
	    ///bug
	    if w.msg_mtazk1proof.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_mtazk1proof.PushBack(msg)
	    if w.msg_mtazk1proof.Len() == (ThresHold-1) {
		fmt.Println("=========Get All MTAZK1PROOF===========","GroupId",w.groupid)
		w.bmtazk1proof <- true
	    }
	    //sign
       case "C11":
	    ///bug
	    if w.msg_c11.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_c11.PushBack(msg)
	    if w.msg_c11.Len() == (ThresHold-1) {
		fmt.Println("=========Get All C11===========","GroupId",w.groupid)
		w.bc11 <- true
	    }
       case "KC":
	    ///bug
	    if w.msg_kc.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_kc.PushBack(msg)
	    if w.msg_kc.Len() == (ThresHold-1) {
		fmt.Println("=========Get All KC===========","GroupId",w.groupid)
		w.bkc <- true
	    }
       case "MKG":
	    ///bug
	    if w.msg_mkg.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_mkg.PushBack(msg)
	    if w.msg_mkg.Len() == (ThresHold-1) {
		fmt.Println("=========Get All MKG===========","GroupId",w.groupid)
		w.bmkg <- true
	    }
       case "MKW":
	    ///bug
	    if w.msg_mkw.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_mkw.PushBack(msg)
	    if w.msg_mkw.Len() == (ThresHold-1) {
		fmt.Println("=========Get All MKW===========","GroupId",w.groupid)
		w.bmkw <- true
	    }
       case "DELTA1":
	    ///bug
	    if w.msg_delta1.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_delta1.PushBack(msg)
	    if w.msg_delta1.Len() == (ThresHold-1) {
		fmt.Println("=========Get All DELTA1===========","GroupId",w.groupid)
		w.bdelta1 <- true
	    }
	case "D11":
	    ///bug
	    if w.msg_d11_1.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_d11_1.PushBack(msg)
	    if w.msg_d11_1.Len() == (ThresHold-1) {
		fmt.Println("=========Get All D11===========","GroupId",w.groupid)
		w.bd11_1 <- true
	    }
	case "S1":
	    ///bug
	    if w.msg_s1.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_s1.PushBack(msg)
	    if w.msg_s1.Len() == (ThresHold-1) {
		fmt.Println("=========Get All S1===========","GroupId",w.groupid)
		w.bs1 <- true
	    }
	case "SS1":
	    ///bug
	    if w.msg_ss1.Len() >= (ThresHold-1) {
		return
	    }
	    ///
	    w.msg_ss1.PushBack(msg)
	    if w.msg_ss1.Len() == (ThresHold-1) {
		fmt.Println("=========Get All SS1===========","GroupId",w.groupid)
		w.bss1 <- true
	    }

	default:
	    fmt.Println("unkown msg code")
	}

	return
}

func IsCurNode(enodes string,cur string) bool {
    if enodes == "" || cur == "" {
	return false
    }

    s := []rune(enodes)
    en := strings.Split(string(s[8:]),"@")
    if en[0] == cur {
	return true
    }

    return false
}

func DoubleHash(id string,keytype string) *big.Int {
    // Generate the random num

    // First, hash with the keccak256
    keccak256 := sha3.NewKeccak256()
    //keccak256.Write(rnd.Bytes())

    keccak256.Write([]byte(id))

    digestKeccak256 := keccak256.Sum(nil)

    //second, hash with the SHA3-256
    sha3256 := sha3.New256()

    sha3256.Write(digestKeccak256)

    digest := sha3256.Sum(nil)
    // convert the hash ([]byte) to big.Int
    digestBigInt := new(big.Int).SetBytes(digest)
    return digestBigInt
}

func GetRandomInt(length int) *big.Int {
	// NewInt allocates and returns a new Int set to x.
	one := big.NewInt(1)
	// Lsh sets z = x << n and returns z.
	maxi := new(big.Int).Lsh(one, uint(length))

	// TODO: Random Seed, need to be replace!!!
	// New returns a new Rand that uses random values from src to generate other random values.
	// NewSource returns a new pseudo-random Source seeded with the given value.
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Rand sets z to a pseudo-random number in [0, n) and returns z.
	rndNum := new(big.Int).Rand(rnd, maxi)
	return rndNum
}

func GetRandomIntFromZn(n *big.Int) *big.Int {
	var rndNumZn *big.Int
	zero := big.NewInt(0)

	for {
		rndNumZn = GetRandomInt(n.BitLen())
		if rndNumZn.Cmp(n) < 0 && rndNumZn.Cmp(zero) >= 0 {
			break
		}
	}

	return rndNumZn
}

func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
    var sa = make([]string, 0)
    for _, v := range DecimalSlice {
        sa = append(sa, fmt.Sprintf("%02X", v))
    }
    ss := strings.Join(sa, "")
    return ss
}

// ReadBits encodes the absolute value of bigint as big-endian bytes. Callers must ensure
// that buf has enough space. If buf is too short the result will be incomplete.
func ReadBits(bigint *big.Int, buf []byte) {
	// number of bits in a big.Word
	wordBits := 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes := wordBits / 8
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

func GetSignString(r *big.Int,s *big.Int,v int32,i int) string {
    rr :=  r.Bytes()
    sss :=  s.Bytes()

    //bug
    if len(rr) == 31 && len(sss) == 32 {
	sigs := make([]byte,65)
	sigs[0] = byte(0)
	ReadBits(r,sigs[1:32])
	ReadBits(s,sigs[32:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    if len(rr) == 31 && len(sss) == 31 {
	sigs := make([]byte,65)
	sigs[0] = byte(0)
	sigs[32] = byte(0)
	ReadBits(r,sigs[1:32])
	ReadBits(s,sigs[33:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    if len(rr) == 32 && len(sss) == 31 {
	sigs := make([]byte,65)
	sigs[32] = byte(0)
	ReadBits(r,sigs[0:32])
	ReadBits(s,sigs[33:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    //

    n := len(rr) + len(sss) + 1
    sigs := make([]byte,n)
    ReadBits(r,sigs[0:len(rr)])
    ReadBits(s,sigs[len(rr):len(rr)+len(sss)])

    sigs[len(rr)+len(sss)] = byte(i)
    ret := Tool_DecimalByteSlice2HexString(sigs)

    return ret
}

func Verify(r *big.Int,s *big.Int,v int32,message string,pkx *big.Int,pky *big.Int) bool {
    return Verify2(r,s,v,message,pkx,pky)
}

func GetEnodesByUid(uid *big.Int,cointype string,groupid string) string {
    _,nodes := GetGroup(groupid)
    others := strings.Split(nodes,SepSg)
    for _,v := range others {
	id := DoubleHash(v,cointype)
	if id.Cmp(uid) == 0 {
	    return v
	}
    }

    return ""
}

type sortableIDSSlice []*big.Int

func (s sortableIDSSlice) Len() int {
	return len(s)
}

func (s sortableIDSSlice) Less(i, j int) bool {
	return s[i].Cmp(s[j]) <= 0
}

func (s sortableIDSSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func GetIds(cointype string,groupid string) sortableIDSSlice {
    var ids sortableIDSSlice
    _,nodes := GetGroup(groupid)
    others := strings.Split(nodes,SepSg)
    for _,v := range others {
	uid := DoubleHash(v,cointype)
	ids = append(ids,uid)
    }
    sort.Sort(ids)
    return ids
}

func GetGroupDir() string { //TODO
    dir := DefaultDataDir()
    dir += "/dcrmdata/dcrmdb" + cur_enode + "group"
    return dir
}

func GetDbDir() string {
    dir := DefaultDataDir()
    dir += "/dcrmdata/dcrmdb" + cur_enode
    return dir
}
func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}
func DefaultDataDir() string {
	home := homeDir()
	if home != "" {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Fusion")
		} else if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming", "Fusion")
		} else {
			return filepath.Join(home, ".fusion")
		}
	}
	// As we cannot guess a stable location, return empty and handle later
	return ""
}

//ec2
//msgprex = hash 
//return value is the backup for dcrm sig.
func dcrm_sign(msgprex string,sig string,txhash string,pubkey string,cointype string,ch chan interface{}) string {

    GetEnodesInfo() 
    
    if int32(Enode_cnts) != int32(NodeCnt) {
	fmt.Println("============the net group is not ready.please try again.================")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("group not ready.")}
	ch <- res
	return ""
    }

    fmt.Println("===================!!!Start!!!====================")

    lock.Lock()
    //db
    dir := GetDbDir()
    db, err := leveldb.OpenFile(dir, nil) 
    if err != nil { 
	fmt.Println("===========open db fail.=============")
        res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("open db fail.")}
        ch <- res
        lock.Unlock()
        return ""
    } 

    //
    pub,err := hex.DecodeString(pubkey)
    if err != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get data fail.")}
	ch <- res
	db.Close()
	lock.Unlock()
	return ""
    }

    var data string
    var b bytes.Buffer 
    b.WriteString("") 
    b.WriteByte(0) 
    b.WriteString("") 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	key := string(iter.Key())
	value := string(iter.Value())
	if strings.EqualFold(key,string(pub)) {
	    data = value
	    break
	}
    }
    iter.Release()
    
    if data == "" {
	fmt.Println("===========get generate save data fail.=============")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get data fail.")}
	ch <- res
	db.Close()
	lock.Unlock()
	return ""
    }

    datas := strings.Split(string(data),Sep)

    save := datas[1] 
    
    dcrmpub := datas[0]
    dcrmpks := []byte(dcrmpub)
    dcrmpkx,dcrmpky := secp256k1.S256().Unmarshal(dcrmpks[:])

    txhashs := []rune(txhash)
    if string(txhashs[0:2]) == "0x" {
	txhash = string(txhashs[2:])
    }

    db.Close()
    lock.Unlock()

    w,err := FindWorker(msgprex)
    if w == nil || err != nil {
	fmt.Println("===========get worker fail.=============")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("no find worker.")}
	ch <- res
	return ""
    }
    id := w.id
    bak_sig := Sign_ec2(msgprex,save,txhash,cointype,dcrmpkx,dcrmpky,ch,id)
    return bak_sig
}

//msgprex = hash
//return value is the backup for the dcrm sig
func Sign_ec2(msgprex string,save string,message string,cointype string,pkx *big.Int,pky *big.Int,ch chan interface{},id int) string {
    //gc := getgroupcount()
    if id < 0 || id >= len(workers) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("no find worker.")}
	ch <- res
	return ""
    }
    w := workers[id]
    GroupId := w.groupid
    fmt.Println("========Sign_ec2============","GroupId",GroupId)
    if GroupId == "" {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get group id fail.")}
	ch <- res
	return ""
    }
    
    hashBytes, err2 := hex.DecodeString(message)
    if err2 != nil {
	res := RpcDcrmRes{Ret:"",Err:err2}
	ch <- res
	return ""
    }

    // [Notes]
    // 1. assume the nodes who take part in the signature generation as follows
    ids := GetIds(cointype,GroupId)
    idSign := ids[:ThresHold]
	
    // 1. map the share of private key to no-threshold share of private key
    var self *big.Int
    lambda1 := big.NewInt(1)
    for _,uid := range idSign {
	enodes := GetEnodesByUid(uid,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    self = uid
	    break
	}
    }

    if self == nil {
	return ""
    }

    for i,uid := range idSign {
	enodes := GetEnodesByUid(uid,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	
	sub := new(big.Int).Sub(idSign[i], self)
	subInverse := new(big.Int).ModInverse(sub,secp256k1.S256().N)
	times := new(big.Int).Mul(subInverse, idSign[i])
	lambda1 = new(big.Int).Mul(lambda1, times)
	lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256().N)
    }
    mm := strings.Split(save, SepSave)
    skU1 := new(big.Int).SetBytes([]byte(mm[0]))
    w1 := new(big.Int).Mul(lambda1, skU1)
    w1 = new(big.Int).Mod(w1,secp256k1.S256().N)
    
    // 2. select k and gamma randomly
    u1K := GetRandomIntFromZn(secp256k1.S256().N)
    u1Gamma := GetRandomIntFromZn(secp256k1.S256().N)
    
    // 3. make gamma*G commitment to get (C, D)
    u1GammaGx,u1GammaGy := secp256k1.S256().ScalarBaseMult(u1Gamma.Bytes())
    commitU1GammaG := new(lib.Commitment).Commit(u1GammaGx, u1GammaGy)

    // 4. Broadcast
    //	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C11"
    s1 := string(commitU1GammaG.C.Bytes())
    ss := enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    //	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
     _,cherr := GetChannelValue(ch_t,w.bc11)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetC11Timeout)}
	ch <- res
	return ""
    }
    
    // 2. MtA(k, gamma) and MtA(k, w)
    // 2.1 encrypt c_k = E_paillier(k)
    var ukc = make(map[string]*big.Int)
    var ukc2 = make(map[string]*big.Int)
    var ukc3 = make(map[string]*lib.PublicKey)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1KCipher,u1R,_ := u1PaillierPk.Encrypt(u1K)
	    ukc[en[0]] = u1KCipher
	    ukc2[en[0]] = u1R
	    ukc3[en[0]] = u1PaillierPk
	    break
	}
    }

    // 2.2 calculate zk(k)
    var zk1proof = make(map[string]*lib.MtAZK1Proof)
    var zkfactproof = make(map[string]*lib.ZkFactProof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	u1zkFactProof := GetZkFactProof(save,k)
	zkfactproof[en[0]] = u1zkFactProof
	if IsCurNode(enodes,cur_enode) {
	    u1u1MtAZK1Proof := lib.MtAZK1Prove(u1K,ukc2[en[0]], ukc3[en[0]], u1zkFactProof)
	    zk1proof[en[0]] = u1u1MtAZK1Proof
	} else {
	    u1u1MtAZK1Proof := lib.MtAZK1Prove(u1K,ukc2[cur_enode], ukc3[cur_enode], u1zkFactProof)
	    mp := []string{msgprex,cur_enode}
	    enode := strings.Join(mp,"-")
	    s0 := "MTAZK1PROOF"
	    s1 := string(u1u1MtAZK1Proof.Z.Bytes()) 
	    s2 := string(u1u1MtAZK1Proof.U.Bytes()) 
	    s3 := string(u1u1MtAZK1Proof.W.Bytes()) 
	    s4 := string(u1u1MtAZK1Proof.S.Bytes()) 
	    s5 := string(u1u1MtAZK1Proof.S1.Bytes()) 
	    s6 := string(u1u1MtAZK1Proof.S2.Bytes()) 
	    ss := enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5 + Sep + s6
	    SendMsgToPeer(enodes,ss)
	}
    }

    _,cherr = GetChannelValue(ch_t,w.bmtazk1proof)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetMTAZK1PROOFTimeout)}
	ch <- res
	return ""
    }

    // 2.3 Broadcast c_k, zk(k)
    // u1KCipher, u2KCipher, u3KCipher
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "KC"
    s1 = string(ukc[cur_enode].Bytes())
    ss = enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,GroupId)

    // 2.4 Receive Broadcast c_k, zk(k)
    // u1KCipher, u2KCipher, u3KCipher
     _,cherr = GetChannelValue(ch_t,w.bkc)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetKCTimeout)}
	ch <- res
	return ""
    }

    var i int
    kcs := make([]string,ThresHold-1)
    if w.msg_kc.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllKCFail)}
	ch <- res
	return ""
    }
    itmp := 0
    iter := w.msg_kc.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	kcs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range kcs {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kc := new(big.Int).SetBytes([]byte(mm[2]))
		ukc[en[0]] = kc
		break
	    }
	}
    }
   
    // example for u1, receive: u1u1MtAZK1Proof from u1, u2u1MtAZK1Proof from u2, u3u1MtAZK1Proof from u3
    mtazk1s := make([]string,ThresHold-1)
    if w.msg_mtazk1proof.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllMTAZK1PROOFFail)}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_mtazk1proof.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	mtazk1s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mtazk1s {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		z := new(big.Int).SetBytes([]byte(mm[2]))
		u := new(big.Int).SetBytes([]byte(mm[3]))
		w := new(big.Int).SetBytes([]byte(mm[4]))
		s := new(big.Int).SetBytes([]byte(mm[5]))
		s1 := new(big.Int).SetBytes([]byte(mm[6]))
		s2 := new(big.Int).SetBytes([]byte(mm[7]))
		mtAZK1Proof := &lib.MtAZK1Proof{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
		zk1proof[en[0]] = mtAZK1Proof
		break
	    }
	}
    }

    // 2.5 verify zk(k)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1rlt1 := zk1proof[cur_enode].MtAZK1Verify(ukc[cur_enode],ukc3[cur_enode],zkfactproof[cur_enode])
	    if !u1rlt1 {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }
	} else {
	    if len(en) <= 0 {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    _,exsit := zk1proof[en[0]]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    _,exsit = ukc[en[0]]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }
	    
	    u1PaillierPk := GetPaillierPk(save,k)
	    if u1PaillierPk == nil {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    _,exsit = zkfactproof[cur_enode]
	    if exsit == false {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }

	    u1rlt1 := zk1proof[en[0]].MtAZK1Verify(ukc[en[0]],u1PaillierPk,zkfactproof[cur_enode])
	    if !u1rlt1 {
		res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMTAZK1PROOFFail)}
		ch <- res
		return ""
	    }
	}
    }

    // 2.6
    // select betaStar randomly, and calculate beta, MtA(k, gamma)
    // select betaStar randomly, and calculate beta, MtA(k, w)
    
    // [Notes]
    // 1. betaStar is in [1, paillier.N - secp256k1.N^2]
    NSalt := new(big.Int).Lsh(big.NewInt(1), uint(PaillierKeyLength-PaillierKeyLength/10))
    NSubN2 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
    NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
    // 2. MinusOne
    MinusOne := big.NewInt(-1)
    
    betaU1Star := make([]*big.Int,ThresHold)
    betaU1 := make([]*big.Int,ThresHold)
    for i=0;i<ThresHold;i++ {
	beta1U1Star := GetRandomIntFromZn(NSubN2)
	beta1U1 := new(big.Int).Mul(MinusOne, beta1U1Star)
	betaU1Star[i] = beta1U1Star
	betaU1[i] = beta1U1
    }

    vU1Star := make([]*big.Int,ThresHold)
    vU1 := make([]*big.Int,ThresHold)
    for i=0;i<ThresHold;i++ {
	v1U1Star := GetRandomIntFromZn(NSubN2)
	v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
	vU1Star[i] = v1U1Star
	vU1[i] = v1U1
    }

    // 2.7
    // send c_kGamma to proper node, MtA(k, gamma)   zk
    var mkg = make(map[string]*big.Int)
    var mkg_mtazk2 = make(map[string]*lib.MtAZK2Proof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1KGamma1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	    beta1U1StarCipher, u1BetaR1,_ := u1PaillierPk.Encrypt(betaU1Star[k])
	    u1KGamma1Cipher = u1PaillierPk.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher) // send to u1
	    u1u1MtAZK2Proof := lib.MtAZK2Prove(u1Gamma, betaU1Star[k], u1BetaR1, ukc[cur_enode],ukc3[cur_enode], zkfactproof[cur_enode])
	    mkg[en[0]] = u1KGamma1Cipher
	    mkg_mtazk2[en[0]] = u1u1MtAZK2Proof
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	u2KGamma1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	beta2U1StarCipher, u2BetaR1,_ := u2PaillierPk.Encrypt(betaU1Star[k])
	u2KGamma1Cipher = u2PaillierPk.HomoAdd(u2KGamma1Cipher, beta2U1StarCipher) // send to u2
	u2u1MtAZK2Proof := lib.MtAZK2Prove(u1Gamma, betaU1Star[k], u2BetaR1, ukc[en[0]],u2PaillierPk,zkfactproof[cur_enode])
	mp = []string{msgprex,cur_enode}
	enode = strings.Join(mp,"-")
	s0 = "MKG"
	s1 = string(u2KGamma1Cipher.Bytes()) 
	//////
	s2 := string(u2u1MtAZK2Proof.Z.Bytes())
	s3 := string(u2u1MtAZK2Proof.ZBar.Bytes())
	s4 := string(u2u1MtAZK2Proof.T.Bytes())
	s5 := string(u2u1MtAZK2Proof.V.Bytes())
	s6 := string(u2u1MtAZK2Proof.W.Bytes())
	s7 := string(u2u1MtAZK2Proof.S.Bytes())
	s8 := string(u2u1MtAZK2Proof.S1.Bytes())
	s9 := string(u2u1MtAZK2Proof.S2.Bytes())
	s10 := string(u2u1MtAZK2Proof.T1.Bytes())
	s11 := string(u2u1MtAZK2Proof.T2.Bytes())
	///////
	ss = enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5 + Sep + s6 + Sep + s7 + Sep + s8 + Sep + s9 + Sep + s10 + Sep + s11
	SendMsgToPeer(enodes,ss)
    }
    
    // 2.8
    // send c_kw to proper node, MtA(k, w)   zk
    var mkw = make(map[string]*big.Int)
    var mkw_mtazk2 = make(map[string]*lib.MtAZK2Proof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1Kw1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], w1)
	    v1U1StarCipher, u1VR1,_ := u1PaillierPk.Encrypt(vU1Star[k])
	    u1Kw1Cipher = u1PaillierPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher) // send to u1
	    u1u1MtAZK2Proof2 := lib.MtAZK2Prove(w1, vU1Star[k], u1VR1, ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode])
	    mkw[en[0]] = u1Kw1Cipher
	    mkw_mtazk2[en[0]] = u1u1MtAZK2Proof2
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	u2Kw1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], w1)
	v2U1StarCipher, u2VR1,_ := u2PaillierPk.Encrypt(vU1Star[k])
	u2Kw1Cipher = u2PaillierPk.HomoAdd(u2Kw1Cipher,v2U1StarCipher) // send to u2
	u2u1MtAZK2Proof2 := lib.MtAZK2Prove(w1, vU1Star[k], u2VR1, ukc[en[0]], u2PaillierPk, zkfactproof[cur_enode])

	mp = []string{msgprex,cur_enode}
	enode = strings.Join(mp,"-")
	s0 = "MKW"
	s1 = string(u2Kw1Cipher.Bytes()) 
	//////
	s2 := string(u2u1MtAZK2Proof2.Z.Bytes())
	s3 := string(u2u1MtAZK2Proof2.ZBar.Bytes())
	s4 := string(u2u1MtAZK2Proof2.T.Bytes())
	s5 := string(u2u1MtAZK2Proof2.V.Bytes())
	s6 := string(u2u1MtAZK2Proof2.W.Bytes())
	s7 := string(u2u1MtAZK2Proof2.S.Bytes())
	s8 := string(u2u1MtAZK2Proof2.S1.Bytes())
	s9 := string(u2u1MtAZK2Proof2.S2.Bytes())
	s10 := string(u2u1MtAZK2Proof2.T1.Bytes())
	s11 := string(u2u1MtAZK2Proof2.T2.Bytes())
	///////

	ss = enode + Sep + s0 + Sep + s1 + Sep + s2 + Sep + s3 + Sep + s4 + Sep + s5 + Sep + s6 + Sep + s7 + Sep + s8 + Sep + s9 + Sep + s10 + Sep + s11
	SendMsgToPeer(enodes,ss)
    }

    // 2.9
    // receive c_kGamma from proper node, MtA(k, gamma)   zk
     _,cherr = GetChannelValue(ch_t,w.bmkg)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetMKGTimeout)}
	ch <- res
	return ""
    }

    mkgs := make([]string,ThresHold-1)
    if w.msg_mkg.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllMKGFail)}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_mkg.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	mkgs[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mkgs {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kg := new(big.Int).SetBytes([]byte(mm[2]))
		mkg[en[0]] = kg
		
		z := new(big.Int).SetBytes([]byte(mm[3]))
		zbar := new(big.Int).SetBytes([]byte(mm[4]))
		t := new(big.Int).SetBytes([]byte(mm[5]))
		v := new(big.Int).SetBytes([]byte(mm[6]))
		w := new(big.Int).SetBytes([]byte(mm[7]))
		s := new(big.Int).SetBytes([]byte(mm[8]))
		s1 := new(big.Int).SetBytes([]byte(mm[9]))
		s2 := new(big.Int).SetBytes([]byte(mm[10]))
		t1 := new(big.Int).SetBytes([]byte(mm[11]))
		t2 := new(big.Int).SetBytes([]byte(mm[12]))
		mtAZK2Proof := &lib.MtAZK2Proof{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
		mkg_mtazk2[en[0]] = mtAZK2Proof
		break
	    }
	}
    }

    // 2.10
    // receive c_kw from proper node, MtA(k, w)    zk
    _,cherr = GetChannelValue(ch_t,w.bmkw)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetMKWTimeout)}
	ch <- res
	return ""
    }

    mkws := make([]string,ThresHold-1)
    if w.msg_mkw.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrGetAllMKWFail)}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_mkw.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	mkws[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mkws {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kw := new(big.Int).SetBytes([]byte(mm[2]))
		mkw[en[0]] = kw

		z := new(big.Int).SetBytes([]byte(mm[3]))
		zbar := new(big.Int).SetBytes([]byte(mm[4]))
		t := new(big.Int).SetBytes([]byte(mm[5]))
		v := new(big.Int).SetBytes([]byte(mm[6]))
		w := new(big.Int).SetBytes([]byte(mm[7]))
		s := new(big.Int).SetBytes([]byte(mm[8]))
		s1 := new(big.Int).SetBytes([]byte(mm[9]))
		s2 := new(big.Int).SetBytes([]byte(mm[10]))
		t1 := new(big.Int).SetBytes([]byte(mm[11]))
		t2 := new(big.Int).SetBytes([]byte(mm[12]))
		mtAZK2Proof := &lib.MtAZK2Proof{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
		mkw_mtazk2[en[0]] = mtAZK2Proof
		break
	    }
	}
    }
    
    // 2.11 verify zk
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	rlt111 := mkg_mtazk2[en[0]].MtAZK2Verify(ukc[cur_enode], mkg[en[0]],ukc3[cur_enode], zkfactproof[en[0]])
	if !rlt111 {
	    res := RpcDcrmRes{Ret:"",Err:GetRetErr(ErrVerifyMKGFail)}
	    ch <- res
	    return ""
	}

	rlt112 := mkw_mtazk2[en[0]].MtAZK2Verify(ukc[cur_enode], mkw[en[0]], ukc3[cur_enode], zkfactproof[en[0]])
	if !rlt112 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("mkw mtazk2 verify fail.")}
	    ch <- res
	    return ""
	}
    }
    
    // 2.12
    // decrypt c_kGamma to get alpha, MtA(k, gamma)
    // MtA(k, gamma)
    var index int
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	if IsCurNode(enodes,cur_enode) {
	    index = k
	    break
	}
    }

    u1PaillierSk := GetPaillierSk(save,index)
    if u1PaillierSk == nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get sk fail.")}
	ch <- res
	return ""
    }

    alpha1 := make([]*big.Int,ThresHold)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	alpha1U1, _ := u1PaillierSk.Decrypt(mkg[en[0]])
	alpha1[k] = alpha1U1
    }

    // 2.13
    // decrypt c_kw to get u, MtA(k, w)
    // MtA(k, w)
    uu1 := make([]*big.Int,ThresHold)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	u1U1, _ := u1PaillierSk.Decrypt(mkw[en[0]])
	uu1[k] = u1U1
    }

    // 2.14
    // calculate delta, MtA(k, gamma)
    delta1 := alpha1[0]
    for i=0;i<ThresHold;i++ {
	if i == 0 {
	    continue
	}
	delta1 = new(big.Int).Add(delta1,alpha1[i])
    }
    for i=0;i<ThresHold;i++ {
	delta1 = new(big.Int).Add(delta1, betaU1[i])
    }

    // 2.15
    // calculate sigma, MtA(k, w)
    sigma1 := uu1[0]
    for i=0;i<ThresHold;i++ {
	if i == 0 {
	    continue
	}
	sigma1 = new(big.Int).Add(sigma1,uu1[i])
    }
    for i=0;i<ThresHold;i++ {
	sigma1 = new(big.Int).Add(sigma1, vU1[i])
    }

    // 3. Broadcast
    // delta: delta1, delta2, delta3
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "DELTA1"
    zero,_ := new(big.Int).SetString("0",10)
    if delta1.Cmp(zero) < 0 { //bug
	s1 = "0" + SepDel + string(delta1.Bytes())
    } else {
	s1 = string(delta1.Bytes())
    }
    ss = enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // delta: delta1, delta2, delta3
     _,cherr = GetChannelValue(ch_t,w.bdelta1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all delta timeout.")}
	ch <- res
	return ""
    }
    
    var delta1s = make(map[string]*big.Int)
    delta1s[cur_enode] = delta1

    dels := make([]string,ThresHold-1)
    if w.msg_delta1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all delta fail.")}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_delta1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	dels[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range dels {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		tmps := strings.Split(mm[2], SepDel)
		if len(tmps) == 2 {
		    del := new(big.Int).SetBytes([]byte(tmps[1]))
		    del = new(big.Int).Sub(zero,del) //bug:-xxxxxxx
		    delta1s[en[0]] = del
		} else {
		    del := new(big.Int).SetBytes([]byte(mm[2]))
		    delta1s[en[0]] = del
		}
		break
	    }
	}
    }
    
    // 2. calculate deltaSum
    var deltaSum *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	deltaSum = delta1s[en[0]]
	break
    }
    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if deltaSum == nil || len(en) < 1 || delta1s[en[0]] == nil {
	    var ret2 Err
	    ret2.Info = "calc deltaSum error"
	    res := RpcDcrmRes{Ret:"",Err:ret2}
	    ch <- res
	    return ""
	}
	deltaSum = new(big.Int).Add(deltaSum,delta1s[en[0]])
    }
    deltaSum = new(big.Int).Mod(deltaSum, secp256k1.S256().N)

    // 3. Broadcast
    // commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "D11"
    dlen := len(commitU1GammaG.D)
    s1 = strconv.Itoa(dlen)

    ss = enode + Sep + s0 + Sep + s1 + Sep
    for _,d := range commitU1GammaG.D {
	ss += string(d.Bytes())
	ss += Sep
    }
    ss = ss + "NULL"
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
    _,cherr = GetChannelValue(ch_t,w.bd11_1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all c11 fail.")}
	ch <- res
	return ""
    }

    d11s := make([]string,ThresHold-1)
    if w.msg_d11_1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all c11 fail.")}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_d11_1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	d11s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    c11s := make([]string,ThresHold-1)
    if w.msg_c11.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get all c11 fail.")}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_c11.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	c11s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    // 2. verify and de-commitment to get GammaG
    
    // for all nodes, construct the commitment by the receiving C and D
    var udecom = make(map[string]*lib.Commitment)
    for _,v := range c11s {
	mm := strings.Split(v, Sep)
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range d11s {
	    mmm := strings.Split(vv, Sep)
	    prex2 := mmm[0]
	    prexs2 := strings.Split(prex2,"-")
	    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
		dlen,_ := strconv.Atoi(mmm[2])
		var gg = make([]*big.Int,0)
		l := 0
		for j:=0;j<dlen;j++ {
		    l++
		    gg = append(gg,new(big.Int).SetBytes([]byte(mmm[2+l])))
		}
		deCommit := &lib.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		udecom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }
    deCommit_commitU1GammaG := &lib.Commitment{C: commitU1GammaG.C, D: commitU1GammaG.D}
    udecom[cur_enode] = deCommit_commitU1GammaG

    // for all nodes, verify the commitment
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	//bug
	if len(en) <= 0 {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return ""
	}
	_,exsit := udecom[en[0]]
	if exsit == false {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return ""
	}
	//

	if udecom[en[0]].Verify() == false {
	    res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify commit fail.")}
	    ch <- res
	    return ""
	}
    }

    // for all nodes, de-commitment
    var ug = make(map[string][]*big.Int)
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	_, u1GammaG := udecom[en[0]].DeCommit()
	ug[en[0]] = u1GammaG
    }

    // for all nodes, calculate the GammaGSum
    var GammaGSumx *big.Int
    var GammaGSumy *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	GammaGSumx = (ug[en[0]])[0]
	GammaGSumy = (ug[en[0]])[1]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	GammaGSumx, GammaGSumy = secp256k1.S256().Add(GammaGSumx, GammaGSumy, (ug[en[0]])[0],(ug[en[0]])[1])
    }
	
    // 3. calculate deltaSum^-1 * GammaGSum
    deltaSumInverse := new(big.Int).ModInverse(deltaSum, secp256k1.S256().N)
    deltaGammaGx, deltaGammaGy := secp256k1.S256().ScalarMult(GammaGSumx, GammaGSumy, deltaSumInverse.Bytes())

    // 4. get r = deltaGammaGx
    r := deltaGammaGx

    if r.Cmp(zero) == 0 {
//	log.Debug("sign error: r equal zero.")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("r == 0.")}
	ch <- res
	return ""
    }
    
    // 5. calculate s
    mMtA,_ := new(big.Int).SetString(message,16)
    
    mk1 := new(big.Int).Mul(mMtA, u1K)
    rSigma1 := new(big.Int).Mul(deltaGammaGx, sigma1)
    us1 := new(big.Int).Add(mk1, rSigma1)
    us1 = new(big.Int).Mod(us1, secp256k1.S256().N)
    
    // 6. calculate S = s * R
    S1x, S1y := secp256k1.S256().ScalarMult(deltaGammaGx, deltaGammaGy, us1.Bytes())
    
    // 7. Broadcast
    // S: S1, S2, S3
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "S1"
    s1 = string(S1x.Bytes())
    s2 := string(S1y.Bytes())
    ss = enode + Sep + s0 + Sep + s1 + Sep + s2
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // S: S1, S2, S3
    _,cherr = GetChannelValue(ch_t,w.bs1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get s1 timeout.")}
	ch <- res
	return ""
    }

    var s1s = make(map[string][]*big.Int)
    s1ss := []*big.Int{S1x,S1y}
    s1s[cur_enode] = s1ss

    us1s := make([]string,ThresHold-1)
    if w.msg_s1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get s1 fail.")}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_s1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	us1s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range us1s {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		x := new(big.Int).SetBytes([]byte(mm[2]))
		y := new(big.Int).SetBytes([]byte(mm[3]))
		tmp := []*big.Int{x,y}
		s1s[en[0]] = tmp
		break
	    }
	}
    }

    // 2. calculate SAll
    var SAllx *big.Int
    var SAlly *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	SAllx = (s1s[en[0]])[0]
	SAlly = (s1s[en[0]])[1]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	SAllx, SAlly = secp256k1.S256().Add(SAllx, SAlly, (s1s[en[0]])[0],(s1s[en[0]])[1])
    }
	
    // 3. verify SAll ?= m*G + r*PK
    mMtAGx, mMtAGy := secp256k1.S256().ScalarBaseMult(mMtA.Bytes())
    rMtAPKx, rMtAPKy := secp256k1.S256().ScalarMult(pkx, pky, deltaGammaGx.Bytes())
    SAllComputex, SAllComputey := secp256k1.S256().Add(mMtAGx, mMtAGy, rMtAPKx, rMtAPKy)

    if SAllx.Cmp(SAllComputex) != 0 || SAlly.Cmp(SAllComputey) != 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("verify SAll != m*G + r*PK in sign ec2.")}
	ch <- res
	return ""
    }

    // 4. Broadcast
    // s: s1, s2, s3
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "SS1"
    s1 = string(us1.Bytes())
    ss = enode + Sep + s0 + Sep + s1
    SendMsgToDcrmGroup(ss,GroupId)

    // 1. Receive Broadcast
    // s: s1, s2, s3
    _,cherr = GetChannelValue(ch_t,w.bss1)
    if cherr != nil {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ss1 timeout.")}
	ch <- res
	return ""
    }

    var ss1s = make(map[string]*big.Int)
    ss1s[cur_enode] = us1

    uss1s := make([]string,ThresHold-1)
    if w.msg_ss1.Len() != (ThresHold-1) {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("get ss1 fail.")}
	ch <- res
	return ""
    }
    itmp = 0
    iter = w.msg_ss1.Front()
    for iter != nil {
	mdss := iter.Value.(string)
	uss1s[itmp] = mdss 
	iter = iter.Next()
	itmp++
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range uss1s {
	    mm := strings.Split(v, Sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		tmp := new(big.Int).SetBytes([]byte(mm[2]))
		ss1s[en[0]] = tmp
		break
	    }
	}
    }

    // 2. calculate s
    var sSum *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	sSum = ss1s[en[0]]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id,cointype,GroupId)
	en := strings.Split(string(enodes[8:]),"@")
	sSum = new(big.Int).Add(sSum,ss1s[en[0]])
    }
    sSum = new(big.Int).Mod(sSum, secp256k1.S256().N) 
   
    // 3. justify the s
    bb := false
    halfN := new(big.Int).Div(secp256k1.S256().N, big.NewInt(2))
    if sSum.Cmp(halfN) > 0 {
	bb = true
	sSum = new(big.Int).Sub(secp256k1.S256().N, sSum)
    }

    s := sSum
    if s.Cmp(zero) == 0 {
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("s == 0.")}
	ch <- res
	return ""
    }

    // **[End-Test]  verify signature with MtA
    signature := new(ECDSASignature)
    signature.New()
    signature.SetR(r)
    signature.SetS(s)

    //v
    recid := secp256k1.Get_ecdsa_sign_v(deltaGammaGx, deltaGammaGy)
    if cointype == "ETH" && bb {
	recid ^=1
    }
    if cointype == "BTC" && bb {
	recid ^= 1
    }

    ////check v
    ys := secp256k1.S256().Marshal(pkx,pky)
    pubkeyhex := hex.EncodeToString(ys)
    pbhs := []rune(pubkeyhex)
    if string(pbhs[0:2]) == "0x" {
	pubkeyhex = string(pbhs[2:])
    }
    
    rsvBytes1 := append(signature.GetR().Bytes(), signature.GetS().Bytes()...)
    for j := 0; j < 4; j++ {
	rsvBytes2 := append(rsvBytes1, byte(j))
	pkr, e := secp256k1.RecoverPubkey(hashBytes,rsvBytes2)
	pkr2 := hex.EncodeToString(pkr)
	pbhs2 := []rune(pkr2)
	if string(pbhs2[0:2]) == "0x" {
		    pkr2 = string(pbhs2[2:])
	}
	if e == nil && strings.EqualFold(pkr2,pubkeyhex) {
		recid = j
		break
	}
    }
    ///// 
    signature.SetRecoveryParam(int32(recid))

    if Verify(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),message,pkx,pky) == false {
	fmt.Println("===================dcrm sign,verify is false=================")
	res := RpcDcrmRes{Ret:"",Err:fmt.Errorf("sign verify fail.")}
	ch <- res
	return ""
    }

    signature2 := GetSignString(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),int(signature.GetRecoveryParam()))
    rstring := "========================== r = " + fmt.Sprintf("%v",signature.GetR()) + " ========================="
    sstring := "========================== s = " + fmt.Sprintf("%v",signature.GetS()) + " =========================="
    fmt.Println(rstring)
    fmt.Println(sstring)
    sigstring := "========================== rsv str = " + signature2 + " ==========================="
    fmt.Println(sigstring)
    res := RpcDcrmRes{Ret:signature2,Err:nil}
    ch <- res
    
    return "" 
}

func GetPaillierPk(save string,index int) *lib.PublicKey {
    if save == "" || index < 0 {
	return nil
    }

    mm := strings.Split(save, SepSave)
    s := 4 + 4*index
    l := mm[s]
    n := new(big.Int).SetBytes([]byte(mm[s+1]))
    g := new(big.Int).SetBytes([]byte(mm[s+2]))
    n2 := new(big.Int).SetBytes([]byte(mm[s+3]))
    publicKey := &lib.PublicKey{Length: l, N: n, G: g, N2: n2}
    return publicKey
}

func GetPaillierSk(save string,index int) *lib.PrivateKey {
    publicKey := GetPaillierPk(save,index)
    if publicKey != nil {
	mm := strings.Split(save, SepSave)
	l := mm[1]
	ll := new(big.Int).SetBytes([]byte(mm[2]))
	uu := new(big.Int).SetBytes([]byte(mm[3]))
	privateKey := &lib.PrivateKey{Length: l, PublicKey: *publicKey, L: ll, U: uu}
	return privateKey
    }

    return nil
}

func GetZkFactProof(save string,index int) *lib.ZkFactProof {
    if save == "" || index < 0 {
	return nil
    }

    mm := strings.Split(save, SepSave)
    s := 4 + 4*NodeCnt + 5*index////????? TODO
    h1 := new(big.Int).SetBytes([]byte(mm[s]))
    h2 := new(big.Int).SetBytes([]byte(mm[s+1]))
    y := new(big.Int).SetBytes([]byte(mm[s+2]))
    e := new(big.Int).SetBytes([]byte(mm[s+3]))
    n := new(big.Int).SetBytes([]byte(mm[s+4]))
    zkFactProof := &lib.ZkFactProof{H1: h1, H2: h2, Y: y, E: e,N: n}
    return zkFactProof
}

func SendMsgToDcrmGroup(msg string,groupid string) {
    BroadcastInGroupOthers(groupid,msg)
}

func SendMsgToPeer(enodes string,msg string) {
    SendToPeer(enodes,msg)
}

// dcrm erros
var (
        //err code 1
	ErrEncodeSendMsgFail   = `{Code:1,Error:"encode send msg fail."}`
	ErrParamError   = `{Code:2,Error:"parameters error."}`
	ErrGetOtherNodesDataFail   = `{Code:3,Error:"NetWork Error,Get Data From Other Node Fail."}`
	ErrUnknownChType   = `{Code:4,Error:"unknown channel type."}`
	ErrGetChValueFail   = `{Code:5,Error:"get channel value fail."}`
	ErrNoGetLOAccout   = `{Code:6,Error:"There's no proper account to do lockout."}`
	ErrNoFindWorker   = `{Code:7,Error:"can not find worker."}`
	ErrOutsideTxFail   = `{Code:8,Error:"outside tx fail."}`
	ErrReqAddrTimeout   = `{Code:9,Error:"request dcrm address timeout."}`
	ErrGetWorkerIdError   = `{Code:10,Error:"get worker id error."}`
	ErrGetPrexDataError   = `{Code:11,Error:"get msg prefix data error."}`
	ErrValidateRealFusionAddrFail   = `{Code:12,Error:"validate real fusion from fail."}`
	ErrValidateRealDcrmFromFail   = `{Code:13,Error:"validate real dcrm from fail."}`
	ErrSendTxToNetFail   = `{Code:14,Error:"send tx to outside net fail."}`
	ErrSendDataToGroupFail   = `{Code:15,Error:"send data to group fail."}`
	ErrInternalMsgFormatError   = `{Code:16,Error:"msg data format error."}`
	ErrGetNoResFromGroupMem   = `{Code:17,Error:"no get any result from other group node."}`
	ErrCoinTypeNotSupported   = `{Code:18,Error:"coin type is not supported."}`
	ErrTokenTypeError   = `{Code:19,Error:"token type error."}`
	ErrValidateLIFromAddrFail   = `{Code:20,Error:"lockin validate from address fail."}`
	ErrValidateLIValueFail   = `{Code:21,Error:"lockin validate value fail."}`
	ErrConfirmAddrFail   = `{Code:22,Error:"the dcrm address confirm validate fail."}`
	ErrGroupNotReady   = `{Code:23,Error:"the group is not ready.please try again."}`
	ErrGetGenPubkeyFail   = `{Code:24,Error:"get generate pubkey fail."}`
	ErrGetGenSaveDataFail   = `{Code:25,Error:"get generate save data fail."}`
	ErrCreateDbFail   = `{Code:26,Error:"create db fail."}`
	ErrGetRealEosUserFail   = `{Code:27,Error:"cannot get real eos account."}`
	ErrDcrmSigWrongSize   = `{Code:28,Error:"wrong size for dcrm sig."}`
	ErrDcrmSigFail   = `{Code:29,Error:"dcrm sign fail."}`
	ErrInvalidDcrmAddr   = `{Code:30,Error:"invalid dcrm address."}`
	ErrGetC1Timeout   = `{Code:31,Error:"get C1 timeout."}`
	ErrGetEnodeByUIdFail   = `{Code:32,Error:"can not find proper enodes by uid."}`
	ErrGetD1Timeout   = `{Code:33,Error:"get D1 timeout."}`
	ErrGetSHARE1Timeout   = `{Code:34,Error:"get SHARE1 timeout."}`
	ErrGetAllSHARE1Fail   = `{Code:35,Error:"get all SHARE1 msg fail."}`
	ErrGetAllD1Fail   = `{Code:36,Error:"get all D1 msg fail."}`
	ErrVerifySHARE1Fail   = `{Code:37,Error:"verify SHARE1 fail."}`
	ErrGetAllC1Fail   = `{Code:38,Error:"get all C1 msg fail."}`
	ErrKeyGenVerifyCommitFail   = `{Code:39,Error:"verify commit in keygenerate fail."}`
	ErrGetZKFACTPROOFTimeout   = `{Code:40,Error:""get ZKFACTPROOF timeout."}`
	ErrGetZKUPROOFTimeout   = `{Code:41,Error:""get ZKUPROOF timeout."}`
	ErrGetAllZKFACTPROOFFail   = `{Code:42,Error:"get all ZKFACTPROOF msg fail."}`
	ErrVerifyZKFACTPROOFFail   = `{Code:43,Error:"verify ZKFACTPROOF fail."}`
	ErrGetAllZKUPROOFFail   = `{Code:44,Error:"get all ZKUPROOF msg fail."}`
	ErrVerifyZKUPROOFFail   = `{Code:45,Error:"verify ZKUPROOF fail."}`
	ErrGetC11Timeout   = `{Code:46,Error:"get C11 timeout."}`
	ErrGetMTAZK1PROOFTimeout   = `{Code:47,Error:"get MTAZK1PROOF timeout."}`
	ErrGetKCTimeout   = `{Code:48,Error:"get KC timeout."}`
	ErrGetAllKCFail   = `{Code:49,Error:"get all KC msg fail."}`
	ErrGetAllMTAZK1PROOFFail   = `{Code:50,Error:"get all MTAZK1PROOF msg fail."}`
	ErrVerifyMTAZK1PROOFFail   = `{Code:51,Error:"verify MTAZK1PROOF fail.""}`
	ErrGetMKGTimeout   = `{Code:52,Error:"get MKG timeout."}`
	ErrGetAllMKGFail   = `{Code:53,Error:"get all MKG msg fail."}`
	ErrGetMKWTimeout   = `{Code:54,Error:"get MKW timeout."}`
	ErrGetAllMKWFail   = `{Code:55,Error:"get all MKW msg fail."}`
	ErrVerifyMKGFail   = `{Code:56,Error:"verify MKG fail.""}`
	ErrVerifyMKWFail   = `{Code:57,Error:"verify MKW fail.""}`
	ErrGetPaillierPrivKeyFail   = `{Code:58,Error:"get paillier privkey fail.""}`
	ErrGetDELTA1Timeout   = `{Code:59,Error:"get DELTA1 timeout."}`
	ErrGetAllDELTA1Fail   = `{Code:60,Error:"get all DELTA1 msg fail."}`
	ErrGetD11Timeout   = `{Code:61,Error:"get D11 timeout."}`
	ErrGetAllD11Fail   = `{Code:62,Error:"get all D11 msg fail."}`
	ErrGetAllC11Fail   = `{Code:63,Error:"get all C11 msg fail."}`
	ErrSignVerifyCommitFail   = `{Code:64,Error:"verify commit in dcrm sign fail."}`
	ErrREqualZero   = `{Code:65,Error:"sign error: r equal zero."}`
	ErrGetS1Timeout   = `{Code:66,Error:"get S1 timeout."}`
	ErrGetAllS1Fail   = `{Code:67,Error:"get all S1 msg fail."}`
	ErrVerifySAllFail   = `{Code:68,Error:"verify SAll != m*G + r*PK in dcrm sign ec2."}`
	ErrGetSS1Timeout   = `{Code:69,Error:"get SS1 timeout."}`
	ErrGetAllSS1Fail   = `{Code:70,Error:"get all SS1 msg fail."}`
	ErrSEqualZero   = `{Code:71,Error:"sign error: s equal zero."}`
	ErrDcrmSignVerifyFail   = `{Code:72,Error:"dcrm sign verify fail."}`
	ErrInvalidCoinbase   = `{Code:73,Error:"Invalid Coinbase."}`
	ErrStateDBError   = `{Code:74,Error:"StateDB Error."}`
	ErrEosAccountNameError   = `{Code:75,Error:"eos account name must be 12 character long, lowercase letters or 1-5."}`
	ErrReqEosPubkeyError   = `{Code:76,Error:"Request eos pubkey error."}`
	
	ErrAlreadyKnownLOTx   = `{Code:101,Error:"already known lockout transaction with same nonce."}`
	ErrOrderAlreadySend   = `{Code:102,Error:"the miner has send order already."}`
	ErrTxDataError   = `{Code:103,Error:"tx input data error."}`
	ErrInvalidDcrmPubkey   = `{Code:104,Error:"invalid dcrm pubkey."}`
	ErrDcrmAddrAlreadyConfirmed  = `{Code:105,Error:"the account has confirmed dcrm address."}`
	ErrDcrmAddrNotConfirmed  = `{Code:106,Error:"the account has not confirmed dcrm address before."}`
	ErrDcrmAddrAlreadyLockIn  = `{Code:107,Error:"the dcrmaddr has lockin alread."}`
	ErrNotRealLockIn  = `{Code:108,Error:"it is not the real lockin,it is BTC change."}`
	ErrInsufficientDcrmFunds  = `{Code:109,Error:"Insufficient Dcrm Funds For Value + Fee."}`
	ErrInvalidAddrToLO  = `{Code:110,Error:"Lock Out To Invalid Address."}`
	ErrLOToSelf  = `{Code:111,Error:"can not lockout to yourself."}`
	ErrInvalidTx  = `{Code:112,Error:"tx data invalid."}`
	ErrHashKeyMiss  = `{Code:113,Error:"hash key and real dcrm from is miss."}`
	
	//TODO
	ErrGetTradeUnitFail  = `{Code:114,Error:"get trade unit fail."}`
	ErrCalcOrderBalance  = `{Code:115,Error:"calc balance error."}`
	
	ErrFromNotFusionAccount  = `{Code:116,Error:"From Must Be Fusion Account In LockOut Tx."}`
	ErrReqAddrInsufficient  = `{Code:117,Error:"Insufficient for req addr,need least 5 fsn."}`
	ErrAddNewTradeInsufficient  = `{Code:118,Error:"Insufficient for add new trade,need least 5 fsn."}`
)

type ErrorRet struct {
    Code int
    Error string
}

func GetRetErrJsonStr(code int,err string) string {
    m := &ErrorRet{Code:code,Error:err}
    ret,_ := json.Marshal(m)
    return string(ret)
}

func GetRetErr(err string) error {
    var ret2 Err
    ret2.Info = err
    return ret2
}

type ECDSASignature struct {
	r *big.Int
	s *big.Int
	recoveryParam int32
	roudFiveAborted bool
}

func (this *ECDSASignature) New() {
}

func (this *ECDSASignature) New2(r *big.Int,s *big.Int) {
    this.r = r
    this.s = s
}

func (this *ECDSASignature) New3(r *big.Int,s *big.Int,recoveryParam int32) {
    this.r =r 
    this.s = s
    this.recoveryParam = recoveryParam
}

func Verify2(r *big.Int,s *big.Int,v int32,message string,pkx *big.Int,pky *big.Int) bool {
    z,_ := new(big.Int).SetString(message,16)
    ss := new(big.Int).ModInverse(s,secp256k1.S256().N)
    zz := new(big.Int).Mul(z,ss)
    u1 := new(big.Int).Mod(zz,secp256k1.S256().N)

    zz2 := new(big.Int).Mul(r,ss)
    u2 := new(big.Int).Mod(zz2,secp256k1.S256().N)
    
    if u1.Sign() == -1 {
		u1.Add(u1,secp256k1.S256().P)
    }
    ug := make([]byte, 32)
    ReadBits(u1, ug[:])
    ugx,ugy := secp256k1.KMulG(ug[:])

    if u2.Sign() == -1 {
		u2.Add(u2,secp256k1.S256().P)
	}
    upk := make([]byte, 32)
    ReadBits(u2,upk[:])
    upkx,upky := secp256k1.S256().ScalarMult(pkx,pky,upk[:])

    xxx,_ := secp256k1.S256().Add(ugx,ugy,upkx,upky)
    xR := new(big.Int).Mod(xxx,secp256k1.S256().N)

    if xR.Cmp(r) == 0 {
	errstring := "============= ECDSA Signature Verify Passed! (r,s) is a Valid Signature ================"
	fmt.Println(errstring)
	return true
    }

    errstring := "================ @@ERROR@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ECDSA Signature Verify NOT Passed! (r,s) is a InValid Siganture! ================"
    fmt.Println(errstring)
    return false
}

func (this *ECDSASignature) GetRoudFiveAborted() bool {
    return this.roudFiveAborted
}

func (this *ECDSASignature) SetRoudFiveAborted(roudFiveAborted bool) {
    this.roudFiveAborted = roudFiveAborted
}

func (this *ECDSASignature) GetR() *big.Int {
    return this.r
}

func (this *ECDSASignature) SetR(r *big.Int) {
    this.r = r
}

func (this *ECDSASignature) GetS() *big.Int {
    return this.s
}

func (this *ECDSASignature) SetS(s *big.Int) {
    this.s = s
}

func (this *ECDSASignature) GetRecoveryParam() int32 {
    return this.recoveryParam
}

func (this *ECDSASignature) SetRecoveryParam(recoveryParam int32) {
    this.recoveryParam = recoveryParam
}

