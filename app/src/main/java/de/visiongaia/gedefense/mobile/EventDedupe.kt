package de.visiongaia.gedefense.mobile

import java.util.LinkedHashMap

class EventDedupe(private val cap:Int=4096,private val windowMs:Long=60_000L){
    private val m=object:LinkedHashMap<String,Long>(cap,0.75f,true){override fun removeEldestEntry(e:MutableMap.MutableEntry<String,Long>?)=size>cap}
    @Synchronized fun shouldEmit(key:String,now:Long=System.currentTimeMillis()):Boolean{val last=m[key];if(last!=null&&now-last<windowMs)return false;m[key]=now;return true}
}
