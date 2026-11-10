# BinaryAnalysis Repository Audit (fill from actual source)

> Do not infer current implementation from architecture documents.
> Record actual branch/commit and cite concrete paths, symbols and call
> relationships.

## Metadata

-   Repository / branch / commit:
-   Python/package versions:
-   Audit date:
-   Scope/exclusions:

## Inventory

  -------------------------------------------------------------------------------------
  Path           Responsibility   Entrypoints/consumers   Dependencies   Evidence
  -------------- ---------------- ----------------------- -------------- --------------

  -------------------------------------------------------------------------------------

## Production module classification

  ------------------------------------------------------------------------------------
  Module                 Actual           Consumers      KEEP /         Reason and
                         responsibility                  REFACTOR /     migration
                                                         REPLACE /      
                                                         REMOVE         
  ---------------------- ---------------- -------------- -------------- --------------
  Frontend                                                              

  IR/CIR                                                                

  Program/CFG/CG                                                        

  Memory/APG                                                            

  Alias                                                                 

  Dataflow/SSE/Demand                                                   

  Solver                                                                

  Taint/Vulnerability                                                   

  Storage/Cache                                                         

  Debugging/Provenance                                                  
  ------------------------------------------------------------------------------------

## Legacy phase references

  ------------------------------------------------------------------------------------
  Reference         File/symbol/CLI/schema   Runtime impact    Remove/migrate/retain
  ----------------- ------------------------ ----------------- -----------------------

  ------------------------------------------------------------------------------------

## `scripts/` dependency impact

  --------------------------------------------------------------------------
  Script         Production     CLI/CI/docs    Reusable       Disposition
                 imports        consumers      capability     
  -------------- -------------- -------------- -------------- --------------

  --------------------------------------------------------------------------

## `tests/` reset impact

-   Legacy tests encoding old architecture:
-   Valuable semantic scenarios/fixtures:
-   Benchmarks to preserve:
-   New verification policy:
-   Risks if no automated verification:

## Dependency graph

``` text
Replace with actual module dependency graph.
```

## Acquisition audit

-   Current input resolution:
-   Frontend invocation:
-   Artifact format:
-   Cache behavior:
-   Schema/fingerprint:
-   Integrity/concurrency/recovery:
-   Provenance persistence:
-   Gaps:

## CTree/HIR feasibility

-   IDA/Hex-Rays versions:
-   Actual structured APIs:
-   Export boundary:
-   Type serialization:
-   Lvar identity/location:
-   Node EA mapping:
-   Unsupported constructs:
-   HIR necessity and lowering feasibility:

## Decision register

  ID   Question   Options   Evidence   Recommendation   Owner decision
  ---- ---------- --------- ---------- ---------------- ----------------

## Risks

  Risk   Impact   Mitigation   Owner
  ------ -------- ------------ -------

## Conclusion

-   Keep:
-   Refactor:
-   Replace:
-   Remove:
-   Required owner decisions:
-   Recommended first implementation slice:
