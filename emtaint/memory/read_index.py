"""Optional list-compatible indexing of the existing immutable ReadMemory DTOs.

No read or guard is merged. Every normal list mutation rebuilds the secondary
index when needed, including same-length edits used by conformance checks.
"""
from collections import Counter


class ReadIndex(list):
    def __init__(self,values=()):
        super().__init__(values);self._rebuild()

    def _rebuild(self):
        self._members=Counter(self);self._by_result={}
        for read in self:self._by_result.setdefault(read.result,[]).append(read)

    def __contains__(self,read):
        try:return read in self._members
        except TypeError:return False

    def for_result(self,reference):return tuple(self._by_result.get(reference,()))

    def append(self,read):
        super().append(read);self._members[read]+=1;self._by_result.setdefault(read.result,[]).append(read)

    def extend(self,values):
        for value in tuple(values) if values is self else values:self.append(value)

    def __setitem__(self,key,value):super().__setitem__(key,value);self._rebuild()
    def __delitem__(self,key):super().__delitem__(key);self._rebuild()
    def insert(self,index,value):super().insert(index,value);self._rebuild()
    def pop(self,index=-1):
        result=super().pop(index);self._rebuild();return result
    def remove(self,value):super().remove(value);self._rebuild()
    def clear(self):super().clear();self._rebuild()
    def reverse(self):super().reverse();self._rebuild()
    def sort(self,*args,**kwargs):super().sort(*args,**kwargs);self._rebuild()
    def __iadd__(self,values):self.extend(values);return self
    def __imul__(self,count):super().__imul__(count);self._rebuild();return self


def records_for(reads,reference):
    if isinstance(reads,ReadIndex):return reads.for_result(reference)
    return tuple(read for read in reads if read.result==reference)
