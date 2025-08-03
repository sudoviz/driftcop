import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { DriftBadge, SignerBadge } from "./DriftBadge";
import { DriftDrawer } from "./DriftDrawer";
import { Search, Filter, Download, RefreshCw, Clock } from "lucide-react";
import { Drift } from "@/types/drift";
import { formatDistanceToNow } from "date-fns";

interface DriftDashboardProps {
  drifts: Drift[];
  onRefresh?: () => void;
  onExport?: (format: 'csv' | 'json') => void;
  onOpenWorkbench?: (driftId: string) => void;
  onDriftUpdated?: () => void;
}

export const DriftDashboard = ({ 
  drifts, 
  onRefresh, 
  onExport, 
  onOpenWorkbench,
  onDriftUpdated
}: DriftDashboardProps) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverities, setSelectedSeverities] = useState<number[]>([]);
  const [selectedEnv, setSelectedEnv] = useState<string>("");
  const [selectedRows, setSelectedRows] = useState<string[]>([]);
  const [drawerDrift, setDrawerDrift] = useState<Drift | null>(null);
  const [sortField, setSortField] = useState<string>("severity");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");

  // Filter and sort drifts
  const filteredDrifts = useMemo(() => {
    let filtered = drifts.filter(drift => {
      const matchesSearch = searchTerm === "" || 
        drift.toolName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        drift.repo?.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        drift.server?.endpoint.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesSeverity = selectedSeverities.length === 0 || 
        selectedSeverities.includes(drift.severity);
      
      const matchesEnv = selectedEnv === "" || selectedEnv === "all" || 
        drift.server?.env === selectedEnv;

      return matchesSearch && matchesSeverity && matchesEnv && !drift.approved;
    });

    // Sort
    filtered.sort((a, b) => {
      let aVal: any, bVal: any;
      
      switch (sortField) {
        case "severity":
          aVal = a.severity;
          bVal = b.severity;
          break;
        case "age":
          aVal = new Date(a.createdAt).getTime();
          bVal = new Date(b.createdAt).getTime();
          break;
        case "repo":
          aVal = a.repo?.name || "";
          bVal = b.repo?.name || "";
          break;
        case "tool":
          aVal = a.toolName;
          bVal = b.toolName;
          break;
        default:
          return 0;
      }
      
      if (sortDirection === "asc") {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });

    return filtered;
  }, [drifts, searchTerm, selectedSeverities, selectedEnv, sortField, sortDirection]);

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDirection("desc");
    }
  };

  const toggleRowSelection = (driftId: string) => {
    setSelectedRows(prev => 
      prev.includes(driftId) 
        ? prev.filter(id => id !== driftId)
        : [...prev, driftId]
    );
  };

  const toggleSeverityFilter = (severity: number) => {
    setSelectedSeverities(prev =>
      prev.includes(severity)
        ? prev.filter(s => s !== severity)
        : [...prev, severity]
    );
  };

  const formatAge = (createdAt: string) => {
    return formatDistanceToNow(new Date(createdAt), { addSuffix: true });
  };

  return (
    <div className="max-w-7xl mx-auto px-6 space-y-4 animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight bg-gradient-primary bg-clip-text text-transparent gradient-animate">
            Drift Dashboard
          </h1>
          <p className="text-muted-foreground">
            Monitor configuration drift across your infrastructure
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="outline" onClick={onRefresh} className="glass-card hover:glow-primary transition-all duration-300">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
          <Button variant="outline" onClick={() => onExport?.('csv')} className="glass-card hover:glow-primary transition-all duration-300">
            <Download className="h-4 w-4" />
            Export CSV
          </Button>
          <Button variant="outline" onClick={() => onExport?.('json')} className="glass-card hover:glow-primary transition-all duration-300">
            <Download className="h-4 w-4" />
            Export JSON
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card className="glass-card hover-lift">
        <CardContent className="pt-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex-1 min-w-[300px]">
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search repos, tools, or endpoints..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 glass border-primary/20 focus:glow-primary transition-all duration-300"
                />
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Severity:</span>
              {[0, 1, 2, 3].map(severity => (
                <Button
                  key={severity}
                  variant={selectedSeverities.includes(severity) ? "default" : "outline"}
                  size="sm"
                  onClick={() => toggleSeverityFilter(severity)}
                >
                  <DriftBadge severity={severity as 0 | 1 | 2 | 3} />
                </Button>
              ))}
            </div>

            <Select value={selectedEnv} onValueChange={setSelectedEnv}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="Environment" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Envs</SelectItem>
                <SelectItem value="prod">Production</SelectItem>
                <SelectItem value="staging">Staging</SelectItem>
                <SelectItem value="dev">Development</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results Summary */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          Showing {filteredDrifts.length} of {drifts.length} drifts
          {selectedRows.length > 0 && (
            <span className="ml-2">
              • {selectedRows.length} selected
            </span>
          )}
        </div>
        
        {selectedRows.length > 0 && (
          <div className="flex items-center gap-2">
            <Button variant="approve" size="sm">
              Approve Selected as Low
            </Button>
            <Button variant="outline" size="sm" onClick={() => setSelectedRows([])}>
              Clear Selection
            </Button>
          </div>
        )}
      </div>

      {/* Table */}
      <Card className="glass-card hover-lift">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-primary/20 glass">
                <tr>
                  <th className="px-3 py-2 text-left">
                    <Checkbox 
                      checked={selectedRows.length === filteredDrifts.length && filteredDrifts.length > 0}
                      onCheckedChange={(checked) => {
                        if (checked) {
                          setSelectedRows(filteredDrifts.map(d => d.id));
                        } else {
                          setSelectedRows([]);
                        }
                      }}
                      className="border-primary/40"
                    />
                  </th>
                  <th 
                    className="px-3 py-2 text-left font-medium cursor-pointer hover:text-primary transition-colors duration-200"
                    onClick={() => handleSort("repo")}
                  >
                    Repo {sortField === "repo" && (sortDirection === "asc" ? "↑" : "↓")}
                  </th>
                  <th className="px-3 py-2 text-left font-medium">Server/Env</th>
                  <th 
                    className="px-3 py-2 text-left font-medium cursor-pointer hover:text-primary transition-colors duration-200"
                    onClick={() => handleSort("tool")}
                  >
                    Tool {sortField === "tool" && (sortDirection === "asc" ? "↑" : "↓")}
                  </th>
                  <th 
                    className="px-3 py-2 text-left font-medium cursor-pointer hover:text-primary transition-colors duration-200"
                    onClick={() => handleSort("severity")}
                  >
                    Severity {sortField === "severity" && (sortDirection === "asc" ? "↑" : "↓")}
                  </th>
                  <th className="px-3 py-2 text-left font-medium">Signer</th>
                  <th 
                    className="px-3 py-2 text-left font-medium cursor-pointer hover:text-primary transition-colors duration-200"
                    onClick={() => handleSort("age")}
                  >
                    Age {sortField === "age" && (sortDirection === "asc" ? "↑" : "↓")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredDrifts.map((drift, index) => (
                  <tr 
                    key={drift.id}
                    className="border-b border-primary/10 hover:bg-primary/5 cursor-pointer transition-all duration-200 animate-fade-in-up"
                    onClick={() => setDrawerDrift(drift)}
                    style={{ animationDelay: `${index * 50}ms` }}
                  >
                    <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                      <Checkbox 
                        checked={selectedRows.includes(drift.id)}
                        onCheckedChange={() => toggleRowSelection(drift.id)}
                        className="border-primary/40"
                      />
                    </td>
                    <td className="px-3 py-2">
                      <div className="font-medium text-sm">{drift.repo?.name}</div>
                    </td>
                    <td className="px-3 py-2">
                      <div className="space-y-1">
                        <div className="font-medium text-xs">{drift.server?.endpoint}</div>
                        <Badge variant="outline" className="text-xs">
                          {drift.server?.env}
                        </Badge>
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
                        {drift.toolName}
                      </code>
                    </td>
                    <td className="px-3 py-2">
                      <DriftBadge severity={drift.severity} />
                    </td>
                    <td className="px-3 py-2">
                      <SignerBadge signerOk={drift.signerOk} />
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        {formatAge(drift.createdAt)}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Drawer */}
      <DriftDrawer
        drift={drawerDrift}
        open={!!drawerDrift}
        onClose={() => setDrawerDrift(null)}
        onOpenWorkbench={onOpenWorkbench}
        onDriftUpdated={onDriftUpdated}
      />
    </div>
  );
};