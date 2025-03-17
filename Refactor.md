
# Refactor EmTaint Architecture

## Directory structure
```text
-- emtaint
    -- data
    -- ir
        -- expressions
        -- statements
    -- analysis
        -- dataflow
            -- xxx
        -- graph
            -- callgraph
            -- cfg
            -- icfg
        -- taint
        -- bugfinder
    -- util
        -- memory
    -- config
    -- frontend
        -- angr
        -- ida
            -- plugins
    -- procedures
    -- main.py
-- docs
-- tests
setup.py
README.md
```
