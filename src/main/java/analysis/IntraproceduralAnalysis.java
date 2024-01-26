package analysis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reporting.Reporter;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.ReturnStmt;
import soot.jimple.Stmt;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInstanceFieldRef;
import soot.jimple.internal.JSpecialInvokeExpr;
import soot.jimple.internal.JimpleLocal;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;

import java.util.HashSet;
import java.util.Set;

/**
 * Class implementing dataflow analysis
 */
public class IntraproceduralAnalysis extends ForwardFlowAnalysis<Unit, Set<FlowAbstraction>> {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final SootMethod method;
    private final Reporter reporter;

    public IntraproceduralAnalysis(Body b, Reporter reporter) {
        super(new ExceptionalUnitGraph(b));
        this.method = b.getMethod();
        this.reporter = reporter;
        System.out.println("\n =============== Analyzing method " + b.getMethod().getSignature());
    }

    // 每个方法初始化的操作（e.g. this赋值，方法传参值）都是 JIdentityStmt

    // 每一个unit进行flowThrough的时候 taintsOut都会清空
    @Override
    protected void flowThrough(Set<FlowAbstraction> taintsIn, Unit d, Set<FlowAbstraction> taintsOut) {
        Stmt s = (Stmt) d;
        logger.info("Unit " + d);


        if (s instanceof JAssignStmt) {
            // 判断是否为赋值操作
            // e.g. r2 = r1
            // e.g. r = getSecret()
            // e.g. TargetClass2.s = r
            // e.g. r = "Hello"

            JAssignStmt as = (JAssignStmt) s;
            Value rightOp = as.getRightOp();
            Value leftOp = as.getLeftOp();

            if (rightOp instanceof JSpecialInvokeExpr) { // 这里判断 instanceof JSpecialInvokeExpr其实是有问题的，因为作者默认getSecret已经是一个私有方法了。
                if (((JSpecialInvokeExpr) rightOp).getMethod().getName().toString().equals("getSecret")) // source找到了
                    taintsOut.add(new FlowAbstraction(d, (Local) leftOp)); // 把左边的加进来
            } else if (rightOp instanceof JimpleLocal) {
                for (FlowAbstraction abs : taintsIn) {
                    if (rightOp == abs.getLocal()) {
                        if (leftOp instanceof JInstanceFieldRef) {
                            // Base Class as Tainted
                            // 只要一个实例中的一个字段被taint了，那么认为这个实例就是被taint的
                            taintsOut.add(new FlowAbstraction(d, (Local) ((JInstanceFieldRef) leftOp).getBase()));
                        } else {
                            taintsOut.add(new FlowAbstraction(d, (Local) leftOp));
                        }
                    }
                }

            }
        } else if (s.containsInvokeExpr()) {
            // 如果包含方法调用的话，则进入该部分
            // e.g. leak(String)
            // containsInvokeExpr只有 JInvokeStmt 和 JAssignStmt 才有可能为true，其他的Stmt都是返回false
            InvokeExpr inv = s.getInvokeExpr();
            if (s instanceof InvokeStmt && inv.getMethod().getName().equals("leak")) { // 判断是不是一个调用方法的表达式，并且方法名称为leak
                for (FlowAbstraction in : taintsIn) {
                    if (inv.getArgs().contains(in.getLocal())) {
                        reporter.report(method, in.getSource(), d);
                    }
                }
            } else {
                // 判断被taint的值是不是被作为参数输入到别的方法中去了
                // 并不是sink node，只是参数含有被taint的值
                for (FlowAbstraction in : taintsIn) {
                    if (inv.getArgs().contains(in.getLocal())) {
                        System.out.println("Tainted Value Passed As Arguument");
                        reporter.report(method, in.getSource(), d);
                    }
                }
            }
        } else if (s instanceof ReturnStmt) {
            // 判断被taint的值会不会被return出去
            for (FlowAbstraction in : taintsIn) {
                if (((ReturnStmt) s).getOp() == in.getLocal()) {
                    System.out.println("Tainted Value Returned");
                    reporter.report(method, in.getSource(), d);
                }
            }
        }

        taintsOut.addAll(taintsIn);
    }

    @Override
    protected Set<FlowAbstraction> newInitialFlow() {
        return new HashSet<FlowAbstraction>();
    }

    @Override
    protected Set<FlowAbstraction> entryInitialFlow() {
        return new HashSet<FlowAbstraction>();
    }

    @Override
    protected void merge(Set<FlowAbstraction> in1, Set<FlowAbstraction> in2, Set<FlowAbstraction> out) {
        out.addAll(in1);
        out.addAll(in2);
    }

    @Override
    protected void copy(Set<FlowAbstraction> source, Set<FlowAbstraction> dest) {
        dest.clear();
        dest.addAll(source);
    }

    @Override
    public void doAnalysis() {
        super.doAnalysis();
    }

}
